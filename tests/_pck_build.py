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


# Godot 4 v2-v4 packs (with optional FileAccessEncrypted directory/entries). The 32-byte
# AES-256 key + 16-byte IV are fixed for deterministic fixtures.
GODOT_KEY = bytes(range(32))
_GODOT_IV = bytes(range(16))
_PACK_DIR_ENCRYPTED = 1 << 0
_PACK_REL_FILEBASE = 1 << 1
_PACK_FILE_ENCRYPTED = 1 << 0


def _aes_cfb_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import CFB
    enc = Cipher(algorithms.AES(key), CFB(iv)).encryptor()
    return enc.update(plaintext) + enc.finalize()


def _fae_wrap(plaintext: bytes, key: bytes) -> bytes:
    """Magicless Godot 4 FileAccessEncrypted blob: md5[16] | len u64 | iv[16] | ct(round_up16)."""
    length = len(plaintext)
    pad = (-length) % 16
    ct = _aes_cfb_encrypt(plaintext + b"\x00" * pad, key, _GODOT_IV)
    return hashlib.md5(plaintext).digest() + struct.pack("<Q", length) + _GODOT_IV + ct


def _entry_record(path: str, offset: int, size: int, md5: bytes, flags: int) -> bytes:
    pb = path.encode("utf-8")
    pb += b"\x00" * ((-len(pb)) % 4)             # pad path to a 4-byte boundary
    return struct.pack("<I", len(pb)) + pb + struct.pack("<QQ", offset, size) + md5 \
        + struct.pack("<I", flags)


def build_pck_v4(files: dict[str, bytes], *, fmt: int = 4,
                 version: tuple[int, int, int] = (4, 3, 0),
                 key: bytes | None = None, enc_dir: bool = False,
                 enc_files: bool = False,
                 entry_flags: dict[str, int] | None = None) -> bytes:
    """A Godot 4 (format v2/v3/v4) standalone pack.

    enc_dir wraps the entry table in a FileAccessEncrypted blob; enc_files wraps each file's
    on-disk bytes (the directory size stays the plaintext length). Both need `key`.

    For v3/v4 (which carry a `dir_offset`) the layout mirrors Godot's packer: file data first,
    then the directory at the end, `PACK_REL_FILEBASE` set, and `dir_offset` pointing at the
    trailing directory — so the parser must honour `dir_offset` rather than read sequentially.
    v2 has no `dir_offset`, so its directory stays immediately after the reserved block.
    """
    items = list(files.items())
    rec_len = sum(len(_entry_record(p, 0, 0, b"\x00" * 16, 0)) for p, _ in items)
    if enc_dir:
        wrap = 16 + 8 + 16 + ((rec_len + 15) // 16 * 16)
        dir_on_disk = 4 + wrap
    else:
        dir_on_disk = 4 + rec_len

    pre_len = 20 + 12 + (8 if fmt >= 3 else 0) + 64
    files_first = fmt >= 3
    data_start = pre_len if files_first else pre_len + dir_on_disk

    records = b""
    blobs: list[bytes] = []
    running = data_start
    for path, content in items:
        flags = (_PACK_FILE_ENCRYPTED if enc_files else 0) | (entry_flags or {}).get(path, 0)
        blob = _fae_wrap(content, key) if enc_files else content      # type: ignore[arg-type]
        records += _entry_record(path, running - data_start, len(content),
                                 hashlib.md5(content).digest(), flags)
        blobs.append(blob)
        running += len(blob)

    dir_start = running if files_first else pre_len
    count_block = struct.pack("<I", len(items))
    dir_block = count_block + (_fae_wrap(records, key) if enc_dir else records)  # type: ignore[arg-type]

    pack_flags = _PACK_DIR_ENCRYPTED if enc_dir else 0
    if files_first:
        pack_flags |= _PACK_REL_FILEBASE
    header = struct.pack("<IIIII", _MAGIC, fmt, *version)
    ext = struct.pack("<IQ", pack_flags, data_start)        # file_base = data start
    if fmt >= 3:
        ext += struct.pack("<Q", dir_start)                 # dir_offset
    body = b"".join(blobs) + dir_block if files_first else dir_block + b"".join(blobs)
    return header + ext + _HDR_RESERVED + body
