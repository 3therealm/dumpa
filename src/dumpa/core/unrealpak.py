"""Zero-dependency Unreal Engine 4 `.pak` parser (footer + legacy index).

Unreal packages cooked assets into a `.pak` container: a footer at EOF
(`FPakInfo`) points at an index, which lists each file's path and an `FPakEntry`
(offset / sizes / compression method / blocks / encrypted flag). This reads that
layout with the stdlib alone (`struct` + `zlib`) — same no-deps ethos as `core.pck`
/ `core.elf`.

Scope (the honest zero-dep boundary):
  * **Extract** entries that are uncompressed, or Zlib/Gzip-compressed, AND unencrypted.
  * **Detect-and-defer** (parse metadata, skip extraction): Oodle/LZ4-compressed blocks
    (proprietary codecs, not in the stdlib), AES-encrypted entries or an encrypted index
    (the stdlib has no AES), and the v10+ path-hash / full-directory index + bit-encoded
    entries (UE4.25+) whose layout is not parsed here. Deferral mirrors the Godot-4 PCK
    posture in `core.pck`: surface version + reason, return no entries, write nothing.

Every read is bounds-checked against the file size and paths are sanitized on extract, so
a hostile or truncated pak degrades to "no entries" / "nothing written", never an over-read
or a path-traversal write.

References: Unreal `IPlatformFilePak.h` (`FPakInfo`, `FPakEntry::Serialize`), pak magic
`0x5A6F12E1`.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

const_magic = 0x5A6F12E1
_MAGIC_LE = struct.pack("<I", const_magic)

# FPakInfo version milestones that change the on-disk layout.
_V_INDEX_ENCRYPTION = 4         # bEncryptedIndex byte present from here on
_V_ENCRYPTION_KEY_GUID = 7      # 16-byte EncryptionKeyGuid precedes the encrypted byte
_V_FNAME_COMPRESSION = 8        # CompressionMethodIndex + a footer name table (vs a legacy enum)
_V_PATH_HASH_INDEX = 10         # new path-hash/full-directory index — not parsed (defer)
_MAX_VERSION = 12               # plausibility guard when scanning for the footer

_HASH_LEN = 20                  # FSHAHash
_COMP_NAME_LEN = 32             # each compression-method name slot
_MAX_FOOTER_TAIL = 4096         # bytes read from EOF to locate + parse the footer
_MAX_ENTRIES = 5_000_000
_MAX_PATH = 4096
_MAX_BLOCKS = 1_000_000
const_copy_chunk_size = 1 << 20
const_max_extract_file_bytes = 512 << 20
const_max_extract_total_bytes = 1 << 30

# Compression-method names we can decompress with the stdlib; everything else defers.
_ZLIB_NAMES = frozenset({"zlib"})
_GZIP_NAMES = frozenset({"gzip"})


@dataclass(frozen=True)
class PakEntry:
    path: str               # path relative to the mount point
    offset: int             # absolute file offset of the entry's data record
    size: int               # compressed (stored) size
    uncompressed_size: int
    compression: str        # "none" | "zlib" | "gzip" | the raw method name (deferred)
    encrypted: bool
    blocks: list[tuple[int, int]] = field(default_factory=list)  # (start, end) absolute offsets


@dataclass(frozen=True)
class Pak:
    version: int
    mount_point: str
    entries: list[PakEntry]
    index_encrypted: bool
    encryption_key_guid: bytes | None       # 16 bytes when present + non-zero, else None
    compression_methods: list[str]          # 1-based index table from the footer
    deferred_reason: str | None             # set when the index could not be parsed


def is_deferred(pak: Pak) -> bool:
    return pak.deferred_reason is not None


def _read_fstring(buf: bytes, pos: int) -> tuple[str, int] | None:
    """Decode an Unreal FString at `pos`; return (text, next_pos) or None on overrun."""
    if pos + 4 > len(buf):
        return None
    (n,) = struct.unpack_from("<i", buf, pos)
    pos += 4
    if n == 0:
        return ("", pos)
    if n > 0:
        if n > _MAX_PATH or pos + n > len(buf):
            return None
        raw = buf[pos:pos + n]
        return (raw.split(b"\x00", 1)[0].decode("utf-8", "replace"), pos + n)
    # negative length: UTF-16LE, abs(n) code units including the null terminator
    count = -n
    if count > _MAX_PATH or pos + count * 2 > len(buf):
        return None
    raw = buf[pos:pos + count * 2]
    return (raw.decode("utf-16-le", "replace").split("\x00", 1)[0], pos + count * 2)


def _method_name(methods: list[str], index: int) -> str:
    """Resolve a CompressionMethodIndex (0 = none, 1-based into the table) to a label."""
    if index == 0:
        return "none"
    name = methods[index - 1] if 1 <= index <= len(methods) else f"method{index}"
    low = name.lower()
    if low in _ZLIB_NAMES:
        return "zlib"
    if low in _GZIP_NAMES:
        return "gzip"
    return low or "none"


def _read_entry(buf: bytes, pos: int, version: int,
                methods: list[str]) -> tuple[PakEntry, int, str] | None:
    """Parse one FPakEntry at `pos`. Returns (entry-without-path, next_pos, raw_method)."""
    if pos + 28 > len(buf):
        return None
    offset, size, usize, method_index = struct.unpack_from("<qqqi", buf, pos)
    pos += 28
    if version < _V_FNAME_COMPRESSION:
        # Legacy enum: 0 none, 1 zlib, 2 gzip, others deferred.
        legacy = {0: "none", 1: "zlib", 2: "gzip"}
        comp = legacy.get(method_index, f"method{method_index}")
    else:
        comp = _method_name(methods, method_index)
    pos += _HASH_LEN                                    # FSHAHash
    if pos > len(buf):
        return None
    blocks: list[tuple[int, int]] = []
    if method_index != 0:
        if pos + 4 > len(buf):
            return None
        (block_count,) = struct.unpack_from("<i", buf, pos)
        pos += 4
        if block_count < 0 or block_count > _MAX_BLOCKS or pos + block_count * 16 > len(buf):
            return None
        for _ in range(block_count):
            start, end = struct.unpack_from("<qq", buf, pos)
            pos += 16
            blocks.append((start, end))
    if pos + 5 > len(buf):
        return None
    (encrypted_flag,) = struct.unpack_from("<B", buf, pos)
    pos += 1
    pos += 4                                            # CompressionBlockSize (u32), unused here
    entry = PakEntry(path="", offset=offset, size=size, uncompressed_size=usize,
                     compression=comp, encrypted=bool(encrypted_flag), blocks=blocks)
    return (entry, pos, comp)


def _serialized_entry_size(version: int, block_count: int) -> int:
    """Byte length of an FPakEntry as written inline before each file's data."""
    size = 28 + _HASH_LEN + 1 + 4
    if block_count > 0:
        size += 4 + block_count * 16
    return size


def _parse_footer(data: bytes, file_size: int) -> tuple[int, int, int, bool, bytes | None,
                                                         list[str]] | None:
    """Locate + parse FPakInfo in the file tail.

    Returns (version, index_offset, index_size, index_encrypted, key_guid, methods) or None.
    """
    # Find the last plausible magic in the tail (the footer's magic sits before the
    # index offset/size/hash, so once located everything we need follows it). The footer
    # fields are absolute file offsets, so the tail's position in the file is not needed.
    search = data
    m = search.rfind(_MAGIC_LE)
    while m >= 0:
        # version, index_offset, index_size, hash follow the magic
        if m + 4 + 4 + 8 + 8 + _HASH_LEN <= len(search):
            (version,) = struct.unpack_from("<I", search, m + 4)
            if 1 <= version <= _MAX_VERSION:
                index_offset, index_size = struct.unpack_from("<qq", search, m + 8)
                if index_offset >= 0 and index_size >= 0 and index_offset + index_size <= file_size:
                    index_encrypted = False
                    key_guid: bytes | None = None
                    if version >= _V_INDEX_ENCRYPTION and m - 1 >= 0:
                        index_encrypted = search[m - 1] != 0
                    if version >= _V_ENCRYPTION_KEY_GUID and m - 1 - 16 >= 0:
                        g = search[m - 17:m - 1]
                        key_guid = g if g != b"\x00" * 16 else None
                    methods = _parse_methods(search, m + 4 + 4 + 8 + 8 + _HASH_LEN, version)
                    return (version, index_offset, index_size, index_encrypted, key_guid, methods)
        m = search.rfind(_MAGIC_LE, 0, m)
    return None


def _parse_methods(buf: bytes, pos: int, version: int) -> list[str]:
    """Read the 32-byte compression-method name slots that follow the hash (v8+)."""
    if version < _V_FNAME_COMPRESSION:
        return []
    methods: list[str] = []
    while pos + _COMP_NAME_LEN <= len(buf):
        slot = buf[pos:pos + _COMP_NAME_LEN]
        pos += _COMP_NAME_LEN
        name = slot.split(b"\x00", 1)[0].decode("ascii", "replace").strip()
        if not name:
            break
        methods.append(name)
    return methods


def parse_standalone(path: Path) -> Pak | None:
    """Parse a `.pak` file: footer at EOF + (for version < 10) the legacy index."""
    try:
        file_size = path.stat().st_size
        tail_len = file_size if file_size < _MAX_FOOTER_TAIL // 8 else _MAX_FOOTER_TAIL
        with path.open("rb") as f:
            f.seek(max(0, file_size - tail_len))
            tail = f.read(tail_len)
            footer = _parse_footer(tail, file_size)
            if footer is None:
                return None
            version, index_offset, index_size, index_encrypted, key_guid, methods = footer
            if index_encrypted:
                return Pak(version, "", [], True, key_guid, methods,
                           "encrypted index (AES; decryption deferred)")
            if version >= _V_PATH_HASH_INDEX:
                return Pak(version, "", [], False, key_guid, methods,
                           f"path-hash index format v{version} (UE4.25+) not supported")
            if index_size <= 0 or index_size > file_size:
                return Pak(version, "", [], False, key_guid, methods, "empty or invalid index")
            f.seek(index_offset)
            index = f.read(index_size)
            if len(index) < index_size:
                return None
            return _parse_legacy_index(version, index, methods, key_guid, file_size)
    except OSError:
        return None


def _parse_legacy_index(version: int, index: bytes, methods: list[str],
                        key_guid: bytes | None, file_size: int) -> Pak | None:
    mp = _read_fstring(index, 0)
    if mp is None:
        return Pak(version, "", [], False, key_guid, methods, "unparseable index mount point")
    mount_point, pos = mp
    if pos + 4 > len(index):
        return Pak(version, mount_point, [], False, key_guid, methods, "truncated index")
    (count,) = struct.unpack_from("<i", index, pos)
    pos += 4
    if count < 0 or count > _MAX_ENTRIES:
        return Pak(version, mount_point, [], False, key_guid, methods, "implausible entry count")
    entries: list[PakEntry] = []
    for _ in range(count):
        named = _read_fstring(index, pos)
        if named is None:
            break
        name, pos = named
        parsed = _read_entry(index, pos, version, methods)
        if parsed is None:
            break
        entry, pos, _raw = parsed
        if entry.offset < 0 or entry.size < 0 or entry.offset + entry.size > file_size:
            continue                                    # entry data runs past EOF — skip
        entries.append(PakEntry(
            path=name, offset=entry.offset, size=entry.size,
            uncompressed_size=entry.uncompressed_size, compression=entry.compression,
            encrypted=entry.encrypted, blocks=entry.blocks))
    return Pak(version, mount_point, entries, False, key_guid, methods, None)


def find_embedded(path: Path) -> int | None:
    """No-op: Unreal does not append paks to the native lib (unlike Godot's GDPC trailer).

    Kept for signature parity with `core.pck.find_embedded`; paks ship as standalone files.
    """
    return None


def _safe_dest(out_dir: Path, rel_path: str) -> Path | None:
    """Map an entry path under out_dir, rejecting traversal/absolute escapes.

    The mount point is the cook root (`../../../Game/`), not a real directory, so it is
    deliberately not joined into the destination — only the per-file path is used, and any
    `..`/absolute/backslash segment makes the whole path unsafe (rejected, not relocated).
    """
    if rel_path.startswith("/") or "\\" in rel_path:
        return None
    parts = rel_path.split("/")
    if not parts or any(seg in ("", ".", "..") for seg in parts):
        return None
    dest = out_dir.joinpath(*parts)
    try:
        dest.resolve().relative_to(out_dir.resolve())
    except ValueError:
        return None
    return dest


def _wbits(comp: str) -> int | None:
    if comp == "zlib":
        return zlib.MAX_WBITS
    if comp == "gzip":
        return zlib.MAX_WBITS | 16
    return None


def _payload_offset(f: BinaryIO, entry: PakEntry, version: int) -> int | None:
    """Return the payload offset for one entry; None if the inline header is malformed."""
    # Each file is written as [inline FPakEntry][data]; re-read the inline header to find
    # where the payload begins.
    f.seek(entry.offset)
    head = f.read(64 + len(entry.blocks) * 16 + _HASH_LEN)
    inline = _read_entry(head, 0, version, [])
    if inline is None:
        return None
    _e, header_size, _raw = inline
    return entry.offset + header_size


def _copy_exact(src: BinaryIO, dst: BinaryIO, size: int) -> int | None:
    remaining = size
    written = 0
    while remaining:
        chunk = src.read(min(const_copy_chunk_size, remaining))
        if not chunk:
            return None
        dst.write(chunk)
        remaining -= len(chunk)
        written += len(chunk)
    return written


def _decompress_range_to_file(comp: str, src: BinaryIO, compressed_size: int,
                              dst: BinaryIO, max_output: int) -> int | None:
    wbits = _wbits(comp)
    if wbits is None or compressed_size < 0 or max_output < 0:
        return None
    dec = zlib.decompressobj(wbits)
    remaining = compressed_size
    written = 0
    try:
        while remaining:
            chunk = src.read(min(const_copy_chunk_size, remaining))
            if not chunk:
                return None
            remaining -= len(chunk)
            data = chunk
            while data:
                allowed = max_output - written
                out = dec.decompress(data, allowed + 1)
                data = dec.unconsumed_tail
                if len(out) > allowed:
                    return None
                if out:
                    dst.write(out)
                    written += len(out)
        tail = dec.flush(max_output - written + 1)
    except zlib.error:
        return None
    if len(tail) > max_output - written:
        return None
    if tail:
        dst.write(tail)
        written += len(tail)
    return written if dec.eof else None


def _write_entry_payload(f: BinaryIO, entry: PakEntry, version: int, dest: Path) -> int | None:
    """Stream one entry to dest; None if malformed, too large, or unsupported."""
    if entry.size < 0 or entry.uncompressed_size < 0:
        return None
    if entry.uncompressed_size > const_max_extract_file_bytes:
        return None
    data_offset = _payload_offset(f, entry, version)
    if data_offset is None:
        return None

    tmp = dest.with_name(f".{dest.name}.tmp")
    try:
        with tmp.open("wb") as out:
            if entry.compression == "none":
                if entry.size > const_max_extract_file_bytes:
                    return None
                f.seek(data_offset)
                written = _copy_exact(f, out, entry.size)
            elif entry.compression in ("zlib", "gzip"):
                if not entry.blocks:
                    f.seek(data_offset)
                    written = _decompress_range_to_file(
                        entry.compression, f, entry.size, out, entry.uncompressed_size)
                else:
                    written = 0
                    for start, end in entry.blocks:
                        if end < start or end - start > entry.size + (1 << 20):
                            return None
                        f.seek(start)
                        n = _decompress_range_to_file(
                            entry.compression, f, end - start, out,
                            entry.uncompressed_size - written)
                        if n is None:
                            return None
                        written += n
                if written != entry.uncompressed_size:
                    return None
            else:
                return None
        tmp.replace(dest)
        return written
    except OSError:
        return None
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def extract(path: Path, pak: Pak, out_dir: Path) -> int:
    """Write each harvestable file under out_dir. Returns the count written.

    Skips deferred paks entirely and, within a parsed pak, skips entries that are encrypted
    or use a non-stdlib codec (Oodle/LZ4) — those are surfaced by the scanner, not extracted.
    """
    if pak.deferred_reason is not None:
        return 0
    written = 0
    total_bytes = 0
    try:
        with path.open("rb") as f:
            for e in pak.entries:
                if e.encrypted or e.compression not in ("none", "zlib", "gzip"):
                    continue
                if e.uncompressed_size < 0 or total_bytes + e.uncompressed_size > const_max_extract_total_bytes:
                    break
                dest = _safe_dest(out_dir, e.path)
                if dest is None:
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                n = _write_entry_payload(f, e, pak.version, dest)
                if n is None:
                    continue
                written += 1
                total_bytes += n
    except OSError:
        return written
    return written
