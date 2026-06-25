"""Zero-dependency Godot PCK (pack) parser for `.pck` archives and embedded packs.

Godot ships game resources in a PCK container — a standalone `*.pck` file or a pack
appended to a binary (`libgodot*.so`) with a trailing `u64 size + "GDPC"` footer. This
reads the format with the stdlib alone (`struct`) — same no-deps ethos as `core.elf` /
`core.axml`: the GDPC header, a file directory (path / offset / size / md5 [/ flags]),
then the file data.

Format v1 (Godot 3.x) has a fixed 64-byte reserved block then the directory. Format v2-v4
(Godot 4.x) insert `pack_flags` + `file_base`; v3/v4 add a `dir_offset` pointing at the
directory, and the directory (and individual files) may be encrypted with Godot's
`FileAccessEncrypted` wrapper (AES-256-CFB). Encrypted entries decrypt only when the caller
supplies the 32-byte key (`core.unrealcrypto.decrypt_aes_cfb`, the optional `dumpa[godot]`
extra); without it they are reported but deferred. Sparse/delta bundles are detected and
deferred (their data lives outside the local PCK).

Every read is bounds-checked against the file size and paths are sanitized on extract, so a
hostile or truncated pack degrades to "no entries" or "nothing written", never an over-read
or a path-traversal write.

References: Godot `core/io/file_access_pack.cpp` (PACK_HEADER_MAGIC, try_open_pack),
`core/io/file_access_encrypted.cpp`, and the embedded-pck trailer written by the exporter.
"""

from __future__ import annotations

import hashlib
import io
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from dumpa.core import unrealcrypto
from dumpa.core.fs import open_resilient

const_magic = b"GDPC"
_TRAILER = struct.Struct("<QI")     # embedded footer: u64 pack size, u32 magic
_MAX_FILES = 100_000            # hard cap on parsed directory entries (anti-DoS)
_MAX_PATH = 4096
_MAX_DIR_BYTES = 64 << 20       # ceiling on a decrypted directory blob (per-count bound applies too)
const_copy_chunk_size = 1 << 20
const_max_extract_file_bytes = 512 << 20
const_max_extract_total_bytes = 1 << 30

# Pack-level flags (pack_flags field, v2+).
PACK_DIR_ENCRYPTED = 1 << 0
PACK_REL_FILEBASE = 1 << 1
PACK_SPARSE_BUNDLE = 1 << 2
# Per-entry flags (v2+).
PACK_FILE_ENCRYPTED = 1 << 0
PACK_FILE_REMOVAL = 1 << 1
PACK_FILE_DELTA = 1 << 2

_FAE_HEADER = struct.Struct("<16sQ16s")     # md5[16], length u64, iv[16]
_AES_BLOCK = 16


@dataclass(frozen=True)
class PckEntry:
    path: str           # res:// path as stored
    offset: int         # data offset relative to the effective file base
    size: int           # plaintext size (Godot stores plaintext length for encrypted entries)
    md5: bytes
    flags: int = 0      # per-entry flags (v2+); 0 for v1


@dataclass(frozen=True)
class Pck:
    fmt_version: int
    godot_version: tuple[int, int, int]
    entries: list[PckEntry]
    base_offset: int                    # absolute file position of the GDPC header
    encrypted: bool                     # v2+ directory-encryption flag (False for v1)
    file_base: int = 0                  # v2+ file_base field (0 for v1)
    pack_flags: int = 0                 # v2+ pack flags (0 for v1)
    deferred_reason: str | None = None  # set when the pack can't be extracted (sparse, no key, …)


def is_encrypted(pck: Pck) -> bool:
    return pck.encrypted


def _effective_base(pck: Pck) -> int:
    """Absolute file offset that entry offsets are measured from."""
    if pck.fmt_version == 1:
        return pck.base_offset
    if pck.fmt_version >= 3 or (pck.pack_flags & PACK_REL_FILEBASE):
        return pck.file_base + pck.base_offset
    return pck.file_base


def parse_standalone(path: Path, key: bytes | None = None) -> Pck | None:
    """Parse a `.pck` whose GDPC header is at the start of the file."""
    try:
        with open_resilient(path) as f:
            if f.read(4) != const_magic:
                return None
    except OSError:
        return None
    return parse_at(path, 0, key)


def find_embedded(path: Path) -> int | None:
    """Locate a pack appended to a binary; return its GDPC header offset, or None."""
    try:
        size = path.stat().st_size
        if size < _TRAILER.size + 4:
            return None
        with open_resilient(path) as f:
            f.seek(size - _TRAILER.size)
            trailer = f.read(_TRAILER.size)
            if len(trailer) < _TRAILER.size:
                return None
            pck_size_raw, magic_raw = _TRAILER.unpack(trailer)
            pck_size = int(pck_size_raw)
            magic = int(magic_raw)
            if struct.pack("<I", magic) != const_magic:
                return None
            start = size - _TRAILER.size - pck_size
            if start < 0:
                return None
            f.seek(start)
            if f.read(4) != const_magic:
                return None
    except OSError:
        return None
    return start


def parse_at(path: Path, start: int, key: bytes | None = None) -> Pck | None:
    """Parse the GDPC header and directory located at byte `start`."""
    try:
        size = path.stat().st_size
        with open_resilient(path) as f:
            f.seek(start)
            head = f.read(20)
            if len(head) < 20 or head[:4] != const_magic:
                return None
            _, fmt, vmaj, vmin, vpat = struct.unpack("<IIIII", head)
            version = (vmaj, vmin, vpat)
            if fmt == 1:
                return _parse_v1(f, start, size, version)
            if fmt in (2, 3, 4):
                return _parse_v2plus(f, start, size, fmt, version, key)
            return None  # unknown/newer format — defer rather than guess
    except OSError:
        return None


def _parse_v1(f: BinaryIO, start: int, size: int, version: tuple[int, int, int]) -> Pck | None:
    f.read(64)      # 16 reserved u32
    cnt = f.read(4)
    if len(cnt) < 4:
        return None
    (count,) = struct.unpack("<I", cnt)
    if count > _MAX_FILES:
        return None
    entries: list[PckEntry] = []
    for _ in range(count):
        plb = f.read(4)
        if len(plb) < 4:
            return None
        (plen,) = struct.unpack("<I", plb)
        if plen == 0 or plen > _MAX_PATH:
            return None
        pb = f.read(plen)
        if len(pb) < plen:
            return None
        meta = f.read(32)       # u64 offset, u64 size, md5[16]
        if len(meta) < 32:
            return None
        offset, fsize = struct.unpack("<QQ", meta[:16])
        if start + offset + fsize > size:
            return None         # entry data runs past EOF — corrupt/unsupported
        entries.append(PckEntry(pb.decode("utf-8", "replace"), offset, fsize, meta[16:32]))
    return Pck(1, version, entries, start, False)


def _parse_v2plus(f: BinaryIO, start: int, size: int, fmt: int,
                  version: tuple[int, int, int], key: bytes | None) -> Pck | None:
    ext = f.read(12)
    if len(ext) < 12:
        return None
    pack_flags, file_base = struct.unpack("<IQ", ext)

    dir_offset: int | None = None
    if fmt >= 3:
        db = f.read(8)
        if len(db) < 8:
            return None
        (dir_offset,) = struct.unpack("<Q", db)

    if len(f.read(64)) < 64:        # 16 reserved u32 (v4 sparse+enc stores a salt here — deferred)
        return None

    encrypted = bool(pack_flags & PACK_DIR_ENCRYPTED)

    def _deferred(reason: str) -> Pck:
        return Pck(fmt, version, [], start, encrypted, file_base, pack_flags, reason)

    if pack_flags & PACK_SPARSE_BUNDLE:
        return _deferred("sparse bundle")

    if dir_offset is not None:
        f.seek(start + dir_offset)

    cnt = f.read(4)                 # plaintext file count, even for an encrypted directory
    if len(cnt) < 4:
        return None
    (count,) = struct.unpack("<I", cnt)
    if count > _MAX_FILES:
        return None

    pck = Pck(fmt, version, [], start, encrypted, file_base, pack_flags)
    eff = _effective_base(pck)

    if encrypted:
        if key is None or not unrealcrypto.aes_available():
            return _deferred("encrypted directory (no key)")
        # One directory entry needs at most 4 + _MAX_PATH + 36 bytes; cap the FAE blob to the
        # plausible directory size so a crafted length can't force a huge read/decrypt.
        max_dir_len = min(_MAX_DIR_BYTES, count * (4 + _MAX_PATH + 36))
        plain = _read_fae(f.read, key, max_len=max_dir_len)
        if plain is None:
            return _deferred("encrypted directory (decrypt failed)")
        entries = _read_entries(io.BytesIO(plain).read, count, eff, size)
    else:
        entries = _read_entries(f.read, count, eff, size)

    if entries is None:
        return _deferred("corrupt directory")
    return Pck(fmt, version, entries, start, encrypted, file_base, pack_flags)


def _read_entries(read: Callable[[int], bytes], count: int, eff_base: int,
                  file_size: int) -> list[PckEntry] | None:
    """Parse `count` v2-v4 directory entries from a read() source (file or decrypted blob)."""
    entries: list[PckEntry] = []
    dir_bytes = 0
    for _ in range(count):
        plb = read(4)
        if len(plb) < 4:
            return None
        (plen,) = struct.unpack("<I", plb)
        if plen == 0 or plen > _MAX_PATH:
            return None
        dir_bytes += 4 + plen + 36          # bound the cumulative on-wire directory size
        if dir_bytes > _MAX_DIR_BYTES:
            return None
        pb = read(plen)             # UTF-8 path + zero padding to a 4-byte boundary
        if len(pb) < plen:
            return None
        meta = read(36)             # u64 offset, u64 size, md5[16], u32 flags
        if len(meta) < 36:
            return None
        offset, fsize = struct.unpack("<QQ", meta[:16])
        (flags,) = struct.unpack("<I", meta[32:36])
        # Godot drops removal entries from the inventory (patch-pack deletions) rather than
        # packing them, so skip them here too.
        if flags & PACK_FILE_REMOVAL:
            continue
        path = pb.split(b"\x00", 1)[0].decode("utf-8", "replace")
        abs_off = eff_base + offset
        if abs_off < 0 or abs_off > file_size:
            return None
        # Plaintext entry data must fit; an encrypted entry's on-disk wrapper is larger than
        # its plaintext size, so only bound-check the start for those.
        if not (flags & PACK_FILE_ENCRYPTED) and abs_off + fsize > file_size:
            return None
        entries.append(PckEntry(path, offset, fsize, meta[16:32], flags))
    return entries


def _read_fae(read: Callable[[int], bytes], key: bytes, *, expected_len: int | None = None,
              max_len: int = const_max_extract_file_bytes) -> bytes | None:
    """Decrypt a magicless Godot 4 FileAccessEncrypted blob: md5[16] | len u64 | iv[16] | ct.

    `expected_len` is the directory's plaintext size for a per-file entry; a wrapper whose
    stored length disagrees is rejected before any ciphertext is read. `max_len` caps the
    accepted length (the directory path uses a tighter, per-count bound) so a hostile header
    cannot force a large read/decrypt ahead of the post-hoc size check.
    """
    hdr = read(_FAE_HEADER.size)
    if len(hdr) < _FAE_HEADER.size:
        return None
    md5, length, iv = _FAE_HEADER.unpack(hdr)
    if expected_len is not None and length != expected_len:
        return None
    if length < 0 or length > max_len:
        return None
    ct_len = (length + _AES_BLOCK - 1) & ~(_AES_BLOCK - 1)
    ct = read(ct_len)
    if len(ct) < ct_len:
        return None
    plain = unrealcrypto.decrypt_aes_cfb(ct, key, iv)
    if plain is None:
        return None
    plain = plain[:length]
    if hashlib.md5(plain).digest() != md5:
        return None
    return plain


def _safe_dest(out_dir: Path, res_path: str) -> Path | None:
    """Map a res:// path under out_dir, rejecting traversal/absolute escapes."""
    p = res_path[6:] if res_path.startswith("res://") else res_path
    if p.startswith("/") or "\\" in p:
        return None
    parts = p.split("/")
    if not parts or any(seg in ("", ".", "..") for seg in parts):
        return None
    dest = out_dir.joinpath(*parts)
    try:
        dest.resolve().relative_to(out_dir.resolve())
    except ValueError:
        return None
    return dest


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


def _atomic_write(dest: Path, produce: Callable[[BinaryIO], int | None]) -> int | None:
    """Run `produce` against a temp file, then atomically replace `dest`. Returns bytes or None."""
    tmp = dest.with_name(f".{dest.name}.tmp")
    try:
        with tmp.open("wb") as out:
            written = produce(out)
            if written is None:
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


def _write_plain_entry(f: BinaryIO, abs_off: int, entry: PckEntry, dest: Path) -> int | None:
    if entry.size < 0 or entry.size > const_max_extract_file_bytes:
        return None

    def produce(out: BinaryIO) -> int | None:
        f.seek(abs_off)
        written = _copy_exact(f, out, entry.size)
        return written if written == entry.size else None

    return _atomic_write(dest, produce)


def _write_encrypted_entry(f: BinaryIO, abs_off: int, entry: PckEntry, dest: Path,
                           key: bytes) -> int | None:
    if entry.size < 0 or entry.size > const_max_extract_file_bytes:
        return None
    f.seek(abs_off)
    plain = _read_fae(f.read, key, expected_len=entry.size)
    if plain is None or len(plain) != entry.size:
        return None
    return _atomic_write(dest, lambda out: out.write(plain))


def extract(path: Path, pck: Pck, out_dir: Path, key: bytes | None = None) -> int:
    """Write each packed file under out_dir. Returns the count written.

    Returns 0 for a deferred pack (sparse, or an encrypted directory with no usable key).
    Per-file-encrypted entries decrypt when `key` is supplied, else are skipped (counted as
    not written); removal/delta entries are always skipped.
    """
    if pck.deferred_reason is not None or not pck.entries:
        return 0
    eff = _effective_base(pck)
    written = 0
    total_bytes = 0
    try:
        with open_resilient(path) as f:
            for e in pck.entries:
                if e.flags & (PACK_FILE_REMOVAL | PACK_FILE_DELTA):
                    continue
                if e.size < 0 or total_bytes + e.size > const_max_extract_total_bytes:
                    break
                dest = _safe_dest(out_dir, e.path)
                if dest is None:
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                abs_off = eff + e.offset
                if e.flags & PACK_FILE_ENCRYPTED:
                    if key is None:
                        continue
                    n = _write_encrypted_entry(f, abs_off, e, dest, key)
                else:
                    n = _write_plain_entry(f, abs_off, e, dest)
                if n is None:
                    continue
                written += 1
                total_bytes += n
    except OSError:
        return written
    return written
