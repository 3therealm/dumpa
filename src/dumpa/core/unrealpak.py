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

from dumpa.core import unrealcrypto

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
    compression_block_size: int = 0   # uncompressed bytes per block (LZ4 needs it per-block)


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
    (block_size,) = struct.unpack_from("<I", buf, pos)  # CompressionBlockSize (uncompressed/block)
    pos += 4
    entry = PakEntry(path="", offset=offset, size=size, uncompressed_size=usize,
                     compression=comp, encrypted=bool(encrypted_flag), blocks=blocks,
                     compression_block_size=block_size)
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


def _decrypt_index(index: bytes, key: bytes | None) -> bytes | None:
    """AES-ECB-decrypt a block-aligned encrypted pak index; None if the key/extra is absent."""
    if key is None or not unrealcrypto.aes_available():
        return None
    if not index or len(index) % 16 != 0:
        return None
    return unrealcrypto.decrypt_aes_ecb(index, key)


def parse_standalone(path: Path, *, aes_key: bytes | None = None) -> Pak | None:
    """Parse a `.pak` file: footer at EOF + (for version < 10) the legacy index.

    An AES-encrypted legacy index is decrypted when `aes_key` and the dumpa[unreal] extra
    (cryptography) are both present; otherwise it stays deferred. The v10+ path-hash /
    full-directory index format is not parsed (deferred) regardless of encryption.
    """
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
            if version >= _V_PATH_HASH_INDEX:
                return Pak(version, "", [], index_encrypted, key_guid, methods,
                           f"path-hash index format v{version} (UE4.25+) not supported")
            if index_size <= 0 or index_size > file_size:
                return Pak(version, "", [], index_encrypted, key_guid, methods,
                           "empty or invalid index")
            f.seek(index_offset)
            index = f.read(index_size)
            if len(index) < index_size:
                return None
            if index_encrypted:
                decrypted = _decrypt_index(index, aes_key)
                if decrypted is None:
                    return Pak(version, "", [], True, key_guid, methods,
                               "encrypted index (AES; decryption deferred — needs dumpa[unreal] + key)")
                index = decrypted
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
            encrypted=entry.encrypted, blocks=entry.blocks,
            compression_block_size=entry.compression_block_size))
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


def _align16(n: int) -> int:
    """Round up to the AES block size (encrypted regions are padded to 16 bytes)."""
    return (n + 15) & ~15


def _read_decrypt(f: BinaryIO, offset: int, raw_size: int, key: bytes) -> bytes | None:
    """Read `raw_size` (block-aligned) bytes at `offset` and AES-ECB decrypt them."""
    if raw_size <= 0 or raw_size % 16 != 0:
        return None
    f.seek(offset)
    data = f.read(raw_size)
    if len(data) != raw_size:
        return None
    return unrealcrypto.decrypt_aes_ecb(data, key)


def _zlib_block_inmem(comp: bytes, wbits: int, max_output: int) -> bytes | None:
    """Inflate one in-memory (decrypted) block, bounded by `max_output`; trailing pad ignored."""
    if max_output < 0:
        return None
    try:
        dec = zlib.decompressobj(wbits)
        out = dec.decompress(comp, max_output)
        if dec.unconsumed_tail:                 # produced more than allowed -> bomb
            return None
        out += dec.flush()
    except zlib.error:
        return None
    return out if dec.eof and len(out) <= max_output else None


def _decrypted_payload(f: BinaryIO, entry: PakEntry, data_offset: int,
                       key: bytes) -> bytes | None:
    """Decrypt (and decompress) one AES-encrypted entry into memory.

    Encrypted entries are bounded by the file cap, so they are handled in memory rather than
    streamed: each on-disk region is padded to the 16-byte block, decrypted, then trimmed
    (uncompressed) or inflated block-by-block (zlib/gzip — zlib stops at its stream end and
    ignores the trailing AES padding).
    """
    if entry.compression == "none":
        raw = _read_decrypt(f, data_offset, _align16(entry.size), key)
        if raw is None or len(raw) < entry.size:
            return None
        return raw[:entry.size]
    wbits = _wbits(entry.compression)
    if wbits is None:
        return None
    if not entry.blocks:
        enc = _read_decrypt(f, data_offset, _align16(entry.size), key)
        if enc is None:
            return None
        return _zlib_block_inmem(enc, wbits, entry.uncompressed_size)
    chunks: list[bytes] = []
    total = 0
    for start, end in entry.blocks:
        if end < start or end - start > entry.size + (1 << 20):
            return None
        enc = _read_decrypt(f, start, end - start, key)
        if enc is None:
            return None
        out = _zlib_block_inmem(enc, wbits, entry.uncompressed_size - total)
        if out is None:
            return None
        chunks.append(out)
        total += len(out)
    return b"".join(chunks) if total == entry.uncompressed_size else None


def _lz4_decompress_padded(comp: bytes, uncompressed_size: int) -> bytes | None:
    """LZ4-block decompress `comp`, tolerating up to 15 bytes of trailing AES padding.

    Unencrypted blocks carry the exact compressed length (trim 0); an encrypted block is
    padded to the 16-byte boundary before encryption, and lz4 rejects trailing bytes, so the
    real length is recovered by trimming within the pad window (the first length that inflates
    to exactly `uncompressed_size` wins).
    """
    for trim in range(16):
        cand = comp[:len(comp) - trim] if trim else comp
        if not cand:
            break
        out = unrealcrypto.decompress_lz4_block(cand, uncompressed_size)
        if out is not None:
            return out
    return None


def _lz4_blocks(f: BinaryIO, entry: PakEntry, data_offset: int, key: bytes) -> bytes | None:
    """Decode an LZ4 entry to bytes, decrypting each block first when the entry is encrypted.

    LZ4 needs the per-block uncompressed size (CompressionBlockSize); held in memory (bounded
    by the file cap) like the encrypted path, since LZ4 blocks are not stream-decodable.
    """
    block_size = entry.compression_block_size or entry.uncompressed_size
    if block_size <= 0:
        return None
    blocks = entry.blocks or [(data_offset, data_offset + entry.size)]
    chunks: list[bytes] = []
    written = 0
    for start, end in blocks:
        if end < start or end - start > entry.size + (1 << 20):
            return None
        f.seek(start)
        comp = f.read(end - start)
        if len(comp) != end - start:
            return None
        if entry.encrypted:
            comp = unrealcrypto.decrypt_aes_ecb(comp, key)
            if comp is None:
                return None
        block_usize = min(block_size, entry.uncompressed_size - written)
        out = _lz4_decompress_padded(comp, block_usize)
        if out is None:
            return None
        chunks.append(out)
        written += len(out)
    return b"".join(chunks) if written == entry.uncompressed_size else None


def _write_bytes(dest: Path, data: bytes) -> int | None:
    """Atomically write `data` to dest via a sibling temp file; None on OS error."""
    tmp = dest.with_name(f".{dest.name}.tmp")
    try:
        with tmp.open("wb") as out:
            out.write(data)
        tmp.replace(dest)
        return len(data)
    except OSError:
        return None
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _write_encrypted_entry(f: BinaryIO, entry: PakEntry, version: int, dest: Path,
                           key: bytes) -> int | None:
    """Decrypt one entry into memory and write it to dest. None if unsupported/malformed."""
    if entry.uncompressed_size > const_max_extract_file_bytes:
        return None
    if entry.compression not in ("none", "zlib", "gzip"):
        return None                             # Oodle encrypted: deferred (LZ4 handled earlier)
    data_offset = _payload_offset(f, entry, version)
    if data_offset is None:
        return None
    plain = _decrypted_payload(f, entry, data_offset, key)
    if plain is None:
        return None
    return _write_bytes(dest, plain)


def _write_entry_payload(f: BinaryIO, entry: PakEntry, version: int, dest: Path,
                         aes_key: bytes | None = None) -> int | None:
    """Stream one entry to dest; None if malformed, too large, or unsupported."""
    if entry.size < 0 or entry.uncompressed_size < 0:
        return None
    if entry.uncompressed_size > const_max_extract_file_bytes:
        return None
    if entry.compression == "lz4":
        if not unrealcrypto.lz4_available():
            return None                         # LZ4 needs the dumpa[unreal] extra
        if entry.encrypted and (aes_key is None or not unrealcrypto.aes_available()):
            return None
        data_offset = _payload_offset(f, entry, version)
        if data_offset is None:
            return None
        plain = _lz4_blocks(f, entry, data_offset, aes_key or b"")
        return _write_bytes(dest, plain) if plain is not None else None
    if entry.encrypted:
        if aes_key is None or not unrealcrypto.aes_available():
            return None
        return _write_encrypted_entry(f, entry, version, dest, aes_key)
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


def extract(path: Path, pak: Pak, out_dir: Path, *, aes_key: bytes | None = None) -> int:
    """Write each harvestable file under out_dir. Returns the count written.

    Skips deferred paks entirely and, within a parsed pak, skips entries using a codec without
    an open decompressor (Oodle). LZ4 entries extract when the `dumpa[unreal]` extra (lz4) is
    installed; AES-encrypted entries extract when a caller `aes_key` is supplied and the extra
    (cryptography) is installed. Anything still unsupported is deferred, not extracted.
    """
    if pak.deferred_reason is not None:
        return 0
    can_decrypt = aes_key is not None and unrealcrypto.aes_available()
    lz4_ok = unrealcrypto.lz4_available()
    written = 0
    total_bytes = 0
    try:
        with path.open("rb") as f:
            for e in pak.entries:
                if e.compression not in ("none", "zlib", "gzip", "lz4"):
                    continue                    # Oodle etc.: deferred
                if e.compression == "lz4" and not lz4_ok:
                    continue                    # LZ4 needs the dumpa[unreal] extra
                if e.encrypted and not can_decrypt:
                    continue
                if e.uncompressed_size < 0 or total_bytes + e.uncompressed_size > const_max_extract_total_bytes:
                    break
                dest = _safe_dest(out_dir, e.path)
                if dest is None:
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                n = _write_entry_payload(f, e, pak.version, dest, aes_key=aes_key)
                if n is None:
                    continue
                written += 1
                total_bytes += n
    except OSError:
        return written
    return written
