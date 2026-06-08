"""Zero-dependency Godot PCK (pack) parser for `.pck` archives and embedded packs.

Godot ships game resources in a PCK container — a standalone `*.pck` file or a pack
appended to a binary (`libgodot*.so`) with a trailing `u64 size + "GDPC"` footer. This
reads the format-v1 (Godot 3.x) layout with the stdlib alone (`struct`) — same no-deps
ethos as `core.elf` / `core.axml`: the GDPC header, a file directory (path / offset /
size / md5), then the file data.

Godot 4 (format v2) inserts `pack_flags` + `file_base` into the header and can encrypt
the directory; v2 is detected and surfaced (version + encryption) but its entries are not
parsed — extraction is deferred. Every read is bounds-checked against the file size and
paths are sanitized on extract, so a hostile or truncated pack degrades to "no entries"
or "nothing written", never an over-read or a path-traversal write.

References: Godot `core/io/file_access_pack.cpp` (PACK_HEADER_MAGIC, try_open_pack) and
the embedded-pck trailer written by the exporter.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

const_magic = b"GDPC"
_TRAILER = struct.Struct("<QI")     # embedded footer: u64 pack size, u32 magic
_MAX_FILES = 5_000_000
_MAX_PATH = 4096


@dataclass(frozen=True)
class PckEntry:
    path: str           # res:// path as stored
    offset: int         # data offset relative to base_offset
    size: int
    md5: bytes


@dataclass(frozen=True)
class Pck:
    fmt_version: int
    godot_version: tuple[int, int, int]
    entries: list[PckEntry]
    base_offset: int            # absolute file position of the GDPC header
    encrypted: bool             # v2 directory-encryption flag (always False for v1)


def is_encrypted(pck: Pck) -> bool:
    return pck.encrypted


def parse_standalone(path: Path) -> Pck | None:
    """Parse a `.pck` whose GDPC header is at the start of the file."""
    try:
        with path.open("rb") as f:
            if f.read(4) != const_magic:
                return None
    except OSError:
        return None
    return parse_at(path, 0)


def find_embedded(path: Path) -> int | None:
    """Locate a pack appended to a binary; return its GDPC header offset, or None."""
    try:
        size = path.stat().st_size
        if size < _TRAILER.size + 4:
            return None
        with path.open("rb") as f:
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


def parse_at(path: Path, start: int) -> Pck | None:
    """Parse the GDPC header (and v1 directory) located at byte `start`."""
    try:
        size = path.stat().st_size
        with path.open("rb") as f:
            f.seek(start)
            head = f.read(20)
            if len(head) < 20 or head[:4] != const_magic:
                return None
            _, fmt, vmaj, vmin, vpat = struct.unpack("<IIIII", head)
            version = (vmaj, vmin, vpat)

            if fmt >= 2:
                # Godot 4: read pack_flags + file_base to surface encryption, then defer.
                ext = f.read(12)
                if len(ext) < 12:
                    return None
                pack_flags, _file_base = struct.unpack("<IQ", ext)
                return Pck(fmt, version, [], start, bool(pack_flags & 1))

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
            return Pck(fmt, version, entries, start, False)
    except OSError:
        return None


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


def extract(path: Path, pck: Pck, out_dir: Path) -> int:
    """Write each packed file under out_dir. Returns the count written; 0 if encrypted/v2."""
    if pck.encrypted or pck.fmt_version >= 2:
        return 0
    written = 0
    try:
        with path.open("rb") as f:
            for e in pck.entries:
                dest = _safe_dest(out_dir, e.path)
                if dest is None:
                    continue
                f.seek(pck.base_offset + e.offset)
                data = f.read(e.size)
                if len(data) < e.size:
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                written += 1
    except OSError:
        return written
    return written
