"""Hand-rolled Unreal Engine 4 `.pak` encoder for tests.

Not a product module — it synthesizes minimal valid `.pak` containers so the
unrealpak-parser and unreal-scanner tests need no real UE export. Emits the
version-8 (FName-based compression) layout the parser reads: a data section where
each file is `[inline FPakEntry][payload]`, a legacy index (mount FString + count +
per-file `[name FString][FPakEntry]`), and the `FPakInfo` footer (optional GUID +
encrypted byte + magic + version + index offset/size + hash + 32-byte method names).
Helpers also build the defer paths: an Oodle-method entry, an encrypted index, and a
v11 (path-hash index) footer.
"""

from __future__ import annotations

import struct
import zlib

_MAGIC = 0x5A6F12E1
_HASH = b"\x00" * 20
_COMP_NAMES = ("Zlib", "Gzip", "Oodle")     # 1-based: index 1=Zlib, 2=Gzip, 3=Oodle
_BLOCK_SIZE = 65536


def _fstring(s: str) -> bytes:
    b = s.encode("utf-8") + b"\x00"
    return struct.pack("<i", len(b)) + b


def _entry(offset: int, size: int, usize: int, method_index: int,
           blocks: list[tuple[int, int]], encrypted: bool) -> bytes:
    out = struct.pack("<qqqi", offset, size, usize, method_index) + _HASH
    if method_index != 0:
        out += struct.pack("<i", len(blocks))
        for s, e in blocks:
            out += struct.pack("<qq", s, e)
    out += struct.pack("<B", 1 if encrypted else 0)
    out += struct.pack("<I", _BLOCK_SIZE)
    return out


def _entry_size(method_index: int, block_count: int) -> int:
    n = 28 + 20 + 1 + 4
    if method_index != 0:
        n += 4 + block_count * 16
    return n


def _methods_table() -> bytes:
    out = b""
    for name in _COMP_NAMES:
        out += name.encode("ascii").ljust(32, b"\x00")
    out += b"\x00" * 32                         # terminator slot
    return out


def _aes_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-ECB encrypt `data`, zero-padded up to the 16-byte block (mirrors UE paks)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    padded = data + b"\x00" * ((-len(data)) % 16)
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(padded) + enc.finalize()


def build_pak(files: dict[str, bytes], *, version: int = 8, mount: str = "../../../Game/",
              compress: str | None = None, encrypt_entries: bool = False,
              method_override: int | None = None, aes_key: bytes | None = None) -> bytes:
    """Build a standalone v8 `.pak`.

    `compress=None` stores files uncompressed; `compress="zlib"`/`"gzip"` deflates each
    into a single block. `method_override` forces the CompressionMethodIndex (e.g. 3 = Oodle)
    to exercise the deferral path. `encrypt_entries` sets each entry's encrypted flag; pass
    `aes_key` too to actually AES-256-ECB encrypt each payload (padded to the 16-byte block,
    with the stored size left unpadded — exactly how UE writes encrypted entries).
    """
    method_index = 0
    if compress == "zlib":
        method_index = 1
    elif compress == "gzip":
        method_index = 2
    if method_override is not None:
        method_index = method_override

    data = b""
    index_entries: list[tuple[str, bytes]] = []
    for path, raw in files.items():
        if method_index == 1:
            payload = zlib.compress(raw)
        elif method_index == 2:
            payload = _gzip(raw)
        else:
            payload = raw
        stored_size = len(payload)              # FPakEntry.size: the unpadded (compressed) size
        if encrypt_entries and aes_key is not None:
            payload = _aes_encrypt(payload, aes_key)    # on-disk bytes: padded + encrypted
        record_offset = len(data)
        block_count = 1 if method_index != 0 else 0
        header_size = _entry_size(method_index, block_count)
        payload_off = record_offset + header_size
        blocks = [(payload_off, payload_off + len(payload))] if method_index != 0 else []
        entry = _entry(record_offset, stored_size, len(raw), method_index, blocks, encrypt_entries)
        assert len(entry) == header_size
        data += entry + payload
        index_entries.append((path, entry))

    index = _fstring(mount) + struct.pack("<i", len(index_entries))
    for name, entry in index_entries:
        index += _fstring(name) + entry
    index_offset = len(data)

    footer = _footer(version, index_offset, len(index), index_encrypted=False)
    return data + index + footer


def build_pak_encrypted_index(version: int = 8) -> bytes:
    """A pak whose footer marks the index AES-encrypted (extraction deferred)."""
    body = b"\x00" * 64
    return body + _footer(version, 0, 0, index_encrypted=True)


def build_pak_pathhash_index(version: int = 11) -> bytes:
    """A v11 footer (path-hash index format the parser does not parse — deferred)."""
    body = b"\x00" * 64
    return body + _footer(version, 0, 0, index_encrypted=False)


def _footer(version: int, index_offset: int, index_size: int, *, index_encrypted: bool) -> bytes:
    out = b""
    if version >= 7:
        out += b"\x00" * 16                     # EncryptionKeyGuid (zero -> None)
    out += struct.pack("<B", 1 if index_encrypted else 0)
    out += struct.pack("<I", _MAGIC)
    out += struct.pack("<I", version)
    out += struct.pack("<qq", index_offset, index_size)
    out += _HASH
    if version >= 8:
        out += _methods_table()
    return out


def _gzip(raw: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    return co.compress(raw) + co.flush()
