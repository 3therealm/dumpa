"""Hand-rolled Godot PCK encoder for tests: build minimal valid GDPC archives.

Not a product module — it lets the PCK-parser and godot-scanner tests synthesize packs
without shipping a real Godot export. Emits the format-v1 (Godot 3.x) layout the parser
reads: the GDPC header, a file directory (path_len / path / offset:u64 / size:u64 /
md5[16]), then the file data. Helpers also wrap a v1 pack as an embedded-in-binary pack
(trailing `u64 size + "GDPC"`), and emit a v2 (Godot 4) header with the encrypted-dir
flag set so the deferral path can be exercised.
"""

from __future__ import annotations

import hashlib
import struct

_MAGIC = 0x43504447       # "GDPC"
_HDR_RESERVED = b"\x00" * 64    # 16 reserved u32


def build_pck(files: dict[str, bytes], version: tuple[int, int, int] = (3, 5, 0)) -> bytes:
    """A standalone Godot 3.x (.pck) archive. Keys are res:// paths, values are bytes."""
    major, minor, patch = version
    header = struct.pack("<IIIII", _MAGIC, 1, major, minor, patch) + _HDR_RESERVED
    header += struct.pack("<I", len(files))
    entries = list(files.items())
    dir_size = sum(4 + len(p.encode("utf-8")) + 8 + 8 + 16 for p, _ in entries)
    running = len(header) + dir_size      # data region starts after header + directory
    directory = b""
    data = b""
    for path, content in entries:
        pb = path.encode("utf-8")
        directory += (struct.pack("<I", len(pb)) + pb
                      + struct.pack("<QQ", running, len(content)) + hashlib.md5(content).digest())
        data += content
        running += len(content)
    return header + directory + data


def embed_in_binary(prefix: bytes, pck: bytes) -> bytes:
    """Append a pck to a stub binary with the embedded trailer (u64 size + GDPC magic)."""
    return prefix + pck + struct.pack("<Q", len(pck)) + struct.pack("<I", _MAGIC)


def build_pck_v2_encrypted(version: tuple[int, int, int] = (4, 2, 0)) -> bytes:
    """A Godot 4 (format v2) header with the encrypted-directory flag set; no entries."""
    major, minor, patch = version
    pack_flags = 1            # bit 0 = encrypted directory
    file_base = 0
    return (struct.pack("<IIIII", _MAGIC, 2, major, minor, patch)
            + struct.pack("<IQ", pack_flags, file_base) + _HDR_RESERVED
            + struct.pack("<I", 0))
