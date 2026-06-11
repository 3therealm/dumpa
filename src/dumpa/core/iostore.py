"""Unreal Engine 5 IoStore container (`.utoc` TOC + `.ucas` data) reader + extractor.

UE5 ships cooked content in the IoStore container: a `.utoc` table-of-contents plus one or
more `.ucas` data partitions. The TOC (`FIoStoreTocHeader`, magic `-==--==--==--==-`) records
the chunk table, the compression-block table, the compression-method names, the container
flags, and a directory index that maps real file paths to chunks.

This parses the full TOC (chunk offset/lengths, compression blocks, method names, and the
directory index → paths) and extracts the chunks it can: per-block AES-ECB decryption with a
caller key, and `None`/Zlib/Gzip/LZ4 decompression. **Oodle blocks stay deferred** (no open
decompressor), and a real UE5 cook is overwhelmingly Oodle — so extraction recovers little
from shipping games by design; the value is the file/method inventory + whatever non-Oodle
chunks exist. AES/LZ4 come from the optional `dumpa[unreal]` extra (absent → those defer).

Every read is bounds-checked; a truncated/foreign file degrades to a header-only TOC (still
reportable) or no extraction, never an over-read. Layout cross-referenced from CUE4Parse and
retoc (which agree verbatim, including the BE 40-bit offset/length vs LE 40-bit block offset).

Reference: Unreal `IO/IoStore.cpp` (`FIoStoreTocResource`, `FIoDirectoryIndexResource`).
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from dumpa.core import unrealcrypto
from dumpa.core.fs import read_bytes_resilient

const_magic = b"-==--==--==--==-"      # 16 bytes
_HEADER_SIZE = 144

# EIoContainerFlags.
_FLAG_COMPRESSED = 1 << 0
_FLAG_ENCRYPTED = 1 << 1
_FLAG_SIGNED = 1 << 2
_FLAG_INDEXED = 1 << 3

# EIoStoreTocVersion milestones.
_V_DIRECTORY_INDEX = 2
_V_PARTITION_SIZE = 3
_V_PERFECT_HASH = 4
_V_PERFECT_HASH_OVERFLOW = 5
_V_REPLACE_HASH = 8

_NONE = 0xFFFFFFFF                      # directory-index sentinel (~0u)
_MAX_CHUNKS = 5_000_000
_MAX_BLOCKS = 10_000_000
_MAX_DIR = 5_000_000
_MAX_NAME_LEN = 256
_MAX_UTOC_BYTES = 256 << 20
_MAX_DEPTH = 4096


class _Trunc(Exception):
    """Internal: a bounds-checked read ran past the buffer (untrusted TOC bytes)."""


class _Cur:
    """Little-endian cursor over a bytes buffer; raises _Trunc on any overrun."""

    __slots__ = ("b", "p")

    def __init__(self, b: bytes, p: int = 0) -> None:
        self.b = b
        self.p = p

    def _need(self, n: int) -> None:
        if n < 0 or self.p + n > len(self.b):
            raise _Trunc

    def i32(self) -> int:
        self._need(4); v = struct.unpack_from("<i", self.b, self.p)[0]; self.p += 4; return v

    def u32(self) -> int:
        self._need(4); v = struct.unpack_from("<I", self.b, self.p)[0]; self.p += 4; return v

    def skip(self, n: int) -> None:
        self._need(n); self.p += n

    def take(self, n: int) -> bytes:
        self._need(n); v = self.b[self.p:self.p + n]; self.p += n; return v

    def fstring(self) -> str:
        self._need(4)
        (length,) = struct.unpack_from("<i", self.b, self.p)
        self.p += 4
        if length == 0:
            return ""
        if length > 0:
            if length > _MAX_NAME_LEN:
                raise _Trunc
            raw = self.take(length)
            return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
        count = -length
        if count > _MAX_NAME_LEN:
            raise _Trunc
        raw = self.take(count * 2)
        return raw.decode("utf-16-le", "replace").split("\x00", 1)[0]


def _align16(n: int) -> int:
    return (n + 15) & ~15


def _align_up(n: int, a: int) -> int:
    return (n + a - 1) // a * a


@dataclass(frozen=True)
class TocFile:
    path: str
    chunk_index: int


@dataclass(frozen=True)
class Toc:
    version: int
    entry_count: int
    compressed_block_count: int
    compression_methods: list[str]          # real names (index 0 = None, name[i] = index i+1)
    directory_index_size: int
    flags: int
    encrypted: bool
    compressed: bool
    indexed: bool
    # Extraction metadata — populated when the body arrays parse, else empty.
    compression_block_size: int = 0
    partition_size: int = 0
    partition_count: int = 1
    chunk_offsets: list[tuple[int, int]] = field(default_factory=list)   # (offset, length)
    blocks: list[tuple[int, int, int, int]] = field(default_factory=list)  # (off, csize, usize, method)
    files: list[TocFile] = field(default_factory=list)


def _parse_header(head: bytes) -> dict[str, int] | None:
    if len(head) < _HEADER_SIZE or head[:16] != const_magic:
        return None
    try:
        version = head[16]
        (entry_count, comp_block_count, _cbe_size, name_count, name_len,
         block_size, dir_index_size, partition_count) = struct.unpack_from("<IIIIIIII", head, 24)
        (container_id,) = struct.unpack_from("<Q", head, 0x38)
        (flags,) = struct.unpack_from("<I", head, 0x50)
        (phf_seed_count,) = struct.unpack_from("<I", head, 0x54)
        (partition_size,) = struct.unpack_from("<Q", head, 0x58)
        (phf_overflow_count,) = struct.unpack_from("<I", head, 0x60)
    except struct.error:
        return None
    return {
        "version": version, "entry_count": entry_count, "comp_block_count": comp_block_count,
        "name_count": name_count, "name_len": name_len, "block_size": block_size,
        "dir_index_size": dir_index_size, "partition_count": partition_count or 1,
        "flags": flags, "phf_seed_count": phf_seed_count, "partition_size": partition_size,
        "phf_overflow_count": phf_overflow_count,
    }


def _parse_body(buf: bytes, h: dict[str, int], aes_key: bytes | None
                ) -> tuple[list[tuple[int, int]], list[tuple[int, int, int, int]],
                           list[str], list[TocFile]] | None:
    """Parse the TOC arrays after the 144-byte header; None if truncated/foreign."""
    version, n, m = h["version"], h["entry_count"], h["comp_block_count"]
    if n > _MAX_CHUNKS or m > _MAX_BLOCKS:
        return None
    try:
        cur = _Cur(buf, _HEADER_SIZE)
        cur.skip(n * 12)                                    # ChunkIds (FIoChunkId[ ])
        raw_ol = cur.take(n * 10)                           # ChunkOffsetLengths (BE 40-bit)
        chunk_offsets = [
            (int.from_bytes(raw_ol[i:i + 5], "big"), int.from_bytes(raw_ol[i + 5:i + 10], "big"))
            for i in range(0, n * 10, 10)]
        if version >= _V_PERFECT_HASH and h["phf_seed_count"] > 0:
            cur.skip(h["phf_seed_count"] * 4)
        if version >= _V_PERFECT_HASH_OVERFLOW and h["phf_overflow_count"] > 0:
            cur.skip(h["phf_overflow_count"] * 4)
        raw_cb = cur.take(m * 12)                           # CompressionBlocks (LE-packed)
        blocks = [
            (int.from_bytes(raw_cb[i:i + 5], "little"),
             int.from_bytes(raw_cb[i + 5:i + 8], "little"),
             int.from_bytes(raw_cb[i + 8:i + 11], "little"),
             raw_cb[i + 11])
            for i in range(0, m * 12, 12)]
        methods = []
        for _ in range(h["name_count"]):
            name = cur.take(h["name_len"]).split(b"\x00", 1)[0].decode("ascii", "replace").strip()
            methods.append(name)
        if h["flags"] & _FLAG_SIGNED:
            hash_size = cur.i32()
            cur.skip(hash_size * 2 + 20 * m)                # toc + block sig + per-block SHA1
        files: list[TocFile] = []
        if version >= _V_DIRECTORY_INDEX and (h["flags"] & _FLAG_INDEXED) and h["dir_index_size"] > 0:
            dir_blob = cur.take(h["dir_index_size"])
            if h["flags"] & _FLAG_ENCRYPTED:
                dir_blob = unrealcrypto.decrypt_aes_ecb(dir_blob, aes_key) if aes_key else None
            if dir_blob is not None:
                files = _parse_directory_index(dir_blob) or []
    except _Trunc:
        return None
    return chunk_offsets, blocks, methods, files


def _parse_directory_index(blob: bytes) -> list[TocFile] | None:
    """Walk FIoDirectoryIndexResource into (path, chunk_index) pairs. Mount root dropped."""
    try:
        cur = _Cur(blob)
        cur.fstring()                                       # MountPoint (cook root; dropped)
        num_dirs = cur.i32()
        if num_dirs < 0 or num_dirs > _MAX_DIR:
            return None
        dirs = [(cur.u32(), cur.u32(), cur.u32(), cur.u32()) for _ in range(num_dirs)]
        num_files = cur.i32()
        if num_files < 0 or num_files > _MAX_DIR:
            return None
        file_entries = [(cur.u32(), cur.u32(), cur.u32()) for _ in range(num_files)]
        num_strings = cur.i32()
        if num_strings < 0 or num_strings > _MAX_DIR:
            return None
        strings = [cur.fstring() for _ in range(num_strings)]
    except _Trunc:
        return None

    def name(idx: int) -> str | None:
        return strings[idx] if 0 <= idx < len(strings) else None

    out: list[TocFile] = []
    seen: set[int] = set()

    def walk(di: int, stack: list[str], depth: int) -> None:
        if di in seen or depth > _MAX_DEPTH or not (0 <= di < len(dirs)):
            return
        seen.add(di)
        dname_idx, first_child, next_sib, first_file = dirs[di]
        pushed = False
        if dname_idx != _NONE:
            nm = name(dname_idx)
            if nm is not None:
                stack.append(nm); pushed = True
        fi = first_file
        guard = 0
        while fi != _NONE and 0 <= fi < len(file_entries) and guard < len(file_entries):
            fname_idx, next_file, user_data = file_entries[fi]
            nm = name(fname_idx)
            if nm is not None:
                out.append(TocFile("/".join([*stack, nm]).lstrip("/"), user_data))
            fi = next_file
            guard += 1
        ci = first_child
        guard = 0
        while ci != _NONE and 0 <= ci < len(dirs) and guard < len(dirs):
            walk(ci, stack, depth + 1)
            ci = dirs[ci][2]
            guard += 1
        if pushed:
            stack.pop()

    if dirs:
        walk(0, [], 0)
    return out


def parse_toc(path: Path, *, aes_key: bytes | None = None) -> Toc | None:
    """Parse a `.utoc`: the FIoStoreTocHeader plus (best-effort) the body arrays + directory
    index. A directory index in an encrypted container needs `aes_key` to recover paths."""
    try:
        if path.stat().st_size > _MAX_UTOC_BYTES:
            return None
        buf = read_bytes_resilient(path)
    except OSError:
        return None
    h = _parse_header(buf)
    if h is None:
        return None
    flags = h["flags"]
    name_count, name_len = h["name_count"], h["name_len"]
    body = _parse_body(buf, h, aes_key)
    if body is not None:
        chunk_offsets, blocks, methods, files = body
    else:
        chunk_offsets, blocks, files = [], [], []
        methods = [f"<{name_count} method name(s), {name_len}B each>"] if name_count else []
    return Toc(
        version=h["version"], entry_count=h["entry_count"],
        compressed_block_count=h["comp_block_count"], compression_methods=methods,
        directory_index_size=h["dir_index_size"], flags=flags,
        encrypted=bool(flags & _FLAG_ENCRYPTED), compressed=bool(flags & _FLAG_COMPRESSED),
        indexed=bool(flags & _FLAG_INDEXED), compression_block_size=h["block_size"],
        partition_size=h["partition_size"] or (1 << 64) - 1, partition_count=h["partition_count"],
        chunk_offsets=chunk_offsets, blocks=blocks, files=files)


def _safe_dest(out_dir: Path, rel_path: str) -> Path | None:
    if not rel_path or rel_path.startswith("/") or "\\" in rel_path:
        return None
    parts = rel_path.split("/")
    if any(seg in ("", ".", "..") for seg in parts):
        return None
    dest = out_dir.joinpath(*parts)
    try:
        dest.resolve().relative_to(out_dir.resolve())
    except ValueError:
        return None
    return dest


def _method_name(methods: list[str], index: int) -> str:
    if index == 0:
        return "none"
    name = methods[index - 1] if 1 <= index <= len(methods) else ""
    return name.lower()


def _decompress_block(method: str, data: bytes, usize: int) -> bytes | None:
    """Decompress one IoStore block; None for Oodle (deferred) or any failure."""
    try:
        if method in ("zlib",):
            out = zlib.decompress(data)
        elif method == "gzip":
            out = zlib.decompress(data, zlib.MAX_WBITS | 16)
        elif method == "lz4":
            out = unrealcrypto.decompress_lz4_block(data, usize)
        else:
            return None                                     # oodle / unknown: deferred
    except zlib.error:
        return None
    if out is None or len(out) != usize:
        return None
    return out


def _read_chunk(toc: Toc, streams: list, chunk_index: int, aes_key: bytes | None) -> bytes | None:
    """Decode one chunk from the .ucas partitions; None on Oodle/failure/out-of-range."""
    if not (0 <= chunk_index < len(toc.chunk_offsets)):
        return None
    offset, length = toc.chunk_offsets[chunk_index]
    cbs = toc.compression_block_size
    if cbs <= 0 or length < 0 or offset < 0:
        return None
    first = offset // cbs
    last = (_align_up(offset + length, cbs) - 1) // cbs if length > 0 else first
    off_in_block = offset % cbs
    remaining = length
    out = bytearray()
    for b in range(first, last + 1):
        if not (0 <= b < len(toc.blocks)):
            return None
        blk_off, csize, usize, method_idx = toc.blocks[b]
        raw_size = _align16(csize) if toc.encrypted else csize
        part_idx = blk_off // toc.partition_size
        part_off = blk_off % toc.partition_size
        if not (0 <= part_idx < len(streams)):
            return None
        f = streams[part_idx]
        try:
            f.seek(part_off)
            raw = f.read(raw_size)
        except OSError:
            return None
        if len(raw) != raw_size:
            return None
        if toc.encrypted:
            raw = unrealcrypto.decrypt_aes_ecb(raw, aes_key)
            if raw is None:
                return None
        comp = raw[:csize]
        if method_idx == 0:
            block_data: bytes | None = comp
        else:
            block_data = _decompress_block(_method_name(toc.compression_methods, method_idx),
                                           comp, usize)
        if block_data is None:
            return None                                     # Oodle or corrupt: defer this chunk
        take = min(cbs - off_in_block, remaining)
        out += block_data[off_in_block:off_in_block + take]
        off_in_block = 0
        remaining -= take
        if remaining <= 0:
            break
    return bytes(out) if len(out) == length else None


def _partition_streams(utoc: Path, count: int):
    """Open the .ucas partition file(s) for a .utoc; [] if the primary .ucas is missing."""
    primary = utoc.with_suffix(".ucas")
    if not primary.is_file():
        return []
    paths = [primary]
    for i in range(1, max(count, 1)):
        part = utoc.with_name(f"{utoc.stem}_s{i}.ucas")
        if not part.is_file():
            break
        paths.append(part)
    return paths


def extract(path: Path, toc: Toc, out_dir: Path, *, aes_key: bytes | None = None) -> int:
    """Extract the directory-index files whose chunks are non-Oodle (and decryptable). Returns
    the count written; Oodle/encrypted-without-key chunks are skipped (deferred), not errors."""
    if not toc.files or not toc.chunk_offsets:
        return 0
    if toc.encrypted and (aes_key is None or not unrealcrypto.aes_available()):
        return 0
    paths = _partition_streams(path, toc.partition_count)
    if not paths:
        return 0
    written = 0
    handles: list = []
    try:
        for p in paths:
            handles.append(p.open("rb"))
        for entry in toc.files:
            dest = _safe_dest(out_dir, entry.path)
            if dest is None:
                continue
            data = _read_chunk(toc, handles, entry.chunk_index, aes_key)
            if data is None:
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            written += 1
    except OSError:
        return written
    finally:
        for hd in handles:
            try:
                hd.close()
            except OSError:
                pass
    return written
