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
_COMP_NAMES = ("Zlib", "Gzip", "Oodle", "LZ4")  # 1-based: 1=Zlib 2=Gzip 3=Oodle 4=LZ4
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
              method_override: int | None = None, aes_key: bytes | None = None,
              encrypt_index: bool = False) -> bytes:
    """Build a standalone v8 `.pak`.

    `compress=None` stores files uncompressed; `compress="zlib"`/`"gzip"`/`"lz4"` compresses
    each into a single block. `method_override` forces the CompressionMethodIndex (e.g. 3 =
    Oodle) to exercise the deferral path. `encrypt_entries` sets each entry's encrypted flag;
    pass `aes_key` too to actually AES-256-ECB encrypt each payload (padded to the 16-byte
    block, stored size left unpadded — as UE writes them). `encrypt_index` likewise AES-encrypts
    the whole legacy index and marks the footer, so the encrypted-index path can be exercised.
    """
    method_index = 0
    if compress == "zlib":
        method_index = 1
    elif compress == "gzip":
        method_index = 2
    elif compress == "lz4":
        method_index = 4
    if method_override is not None:
        method_index = method_override

    data = b""
    index_entries: list[tuple[str, bytes]] = []
    for path, raw in files.items():
        if method_index == 1:
            payload = zlib.compress(raw)
        elif method_index == 2:
            payload = _gzip(raw)
        elif method_index == 4:
            payload = _lz4(raw)
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
    if encrypt_index and aes_key is not None:
        index = _aes_encrypt(index, aes_key)        # on-disk index: padded + encrypted
    index_offset = len(data)

    footer = _footer(version, index_offset, len(index), index_encrypted=encrypt_index)
    return data + index + footer


def build_pak_encrypted_index(version: int = 8) -> bytes:
    """A pak with a real legacy index whose footer marks it AES-encrypted.

    No key is baked in, so the parser hits the encrypted-index branch and defers (the
    with-key decryption path is exercised by `build_pak(..., encrypt_index=True, aes_key=...)`).
    """
    return build_pak({"Content/notes.txt": b"hello"}, version=version, encrypt_index=True)


def build_pak_pathhash_index(version: int = 11) -> bytes:
    """A v11 primary index lacking a full directory index — paths unrecoverable, so deferred."""
    mount = "../../../Game/"
    primary = (_fstring(mount) + struct.pack("<i", 0) + struct.pack("<Q", 0)
               + struct.pack("<i", 0)            # bReaderHasPathHashIndex = 0
               + struct.pack("<i", 0)            # bReaderHasFullDirectoryIndex = 0 -> defer
               + struct.pack("<i", 0)            # EncodedPakEntries (empty)
               + struct.pack("<i", 0))           # NumNonEncodedEntries
    body = b"\x00" * 64
    return body + primary + _footer(version, len(body), len(primary), index_encrypted=False)


def _split_path(path: str) -> tuple[str, str]:
    """Split a relative pak path into (dir, filename); dir carries leading + trailing '/'."""
    if "/" in path:
        head, tail = path.rsplit("/", 1)
        return "/" + head + "/", tail
    return "/", path


def _encode_pathhash_entry(offset: int, stored_size: int, usize: int, method_index: int,
                           encrypted: bool, block_size: int, block_sizes: list[int]) -> bytes:
    """Bit-encode one FPakEntry exactly per DecodePakEntry (repak/CUE4Parse layout)."""
    off_u32 = offset <= 0xffffffff
    usize_u32 = usize <= 0xffffffff
    size_u32 = stored_size <= 0xffffffff
    block_count = len(block_sizes) if method_index != 0 else 0
    value = 0
    if off_u32:
        value |= (1 << 31)
    if usize_u32:
        value |= (1 << 30)
    if size_u32:
        value |= (1 << 29)
    value |= (method_index & 0x3f) << 23
    if encrypted:
        value |= (1 << 22)
    value |= (block_count & 0xffff) << 6
    extra = b""
    if method_index != 0:
        token = block_size >> 11
        if token <= 0x3e and (token << 11) == block_size:
            value |= token
        else:
            value |= 0x3f
            extra = struct.pack("<I", block_size)
    out = struct.pack("<I", value) + extra
    out += struct.pack("<I", offset) if off_u32 else struct.pack("<q", offset)
    out += struct.pack("<I", usize) if usize_u32 else struct.pack("<q", usize)
    if method_index != 0:
        out += struct.pack("<I", stored_size) if size_u32 else struct.pack("<q", stored_size)
        if not (block_count == 1 and not encrypted):   # single unencrypted block stores no sizes
            for bs in block_sizes:
                out += struct.pack("<I", bs)
    return out


def build_pak_pathhash(files: dict[str, bytes], *, version: int = 11,
                       mount: str = "../../../Game/", compress: str | None = None,
                       encrypt_entries: bool = False, encrypt_index: bool = False,
                       aes_key: bytes | None = None) -> bytes:
    """Build a UE4.25+ v11 pak with a path-hash primary index + full directory index.

    Layout: [data records][full directory index][primary index][footer]. Supports uncompressed
    and zlib single-block entries, optionally with AES-encrypted entries and/or index — enough
    to exercise the v10+ decode path end to end.
    """
    method_index = {None: 0, "zlib": 1, "gzip": 2, "lz4": 4}[compress]

    data = b""
    encoded = b""
    dir_map: dict[str, list[tuple[str, int]]] = {}
    for path, raw in files.items():
        if method_index == 1:
            payload = zlib.compress(raw)
        elif method_index == 2:
            payload = _gzip(raw)
        elif method_index == 4:
            payload = _lz4(raw)
        else:
            payload = raw
        stored_size = len(payload)
        if encrypt_entries and aes_key is not None:
            payload = _aes_encrypt(payload, aes_key)
        record_offset = len(data)
        block_count = 1 if method_index != 0 else 0
        header_size = _entry_size(method_index, block_count)
        payload_off = record_offset + header_size
        blocks_abs = [(payload_off, payload_off + len(payload))] if method_index != 0 else []
        inline = _entry(record_offset, stored_size, len(raw), method_index, blocks_abs, encrypt_entries)
        assert len(inline) == header_size
        data += inline + payload

        enc_off = len(encoded)
        block_sizes = [stored_size] if method_index != 0 else []
        encoded += _encode_pathhash_entry(record_offset, stored_size, len(raw), method_index,
                                          encrypt_entries, _BLOCK_SIZE, block_sizes)
        d, fname = _split_path(path)
        dir_map.setdefault(d, []).append((fname, enc_off))

    fdi = struct.pack("<i", len(dir_map))
    for d, items in dir_map.items():
        fdi += _fstring(d) + struct.pack("<i", len(items))
        for fname, enc_off in items:
            fdi += _fstring(fname) + struct.pack("<i", enc_off)
    if encrypt_index and aes_key is not None:
        fdi = _aes_encrypt(fdi, aes_key)
    fdi_offset = len(data)

    primary = (_fstring(mount) + struct.pack("<i", len(files)) + struct.pack("<Q", 0)
               + struct.pack("<i", 0)                       # bReaderHasPathHashIndex = 0
               + struct.pack("<i", 1)                       # bReaderHasFullDirectoryIndex = 1
               + struct.pack("<q", fdi_offset) + struct.pack("<q", len(fdi)) + _HASH
               + struct.pack("<i", len(encoded)) + encoded
               + struct.pack("<i", 0))                      # NumNonEncodedEntries
    if encrypt_index and aes_key is not None:
        primary = _aes_encrypt(primary, aes_key)
    index_offset = len(data) + len(fdi)
    footer = _footer(version, index_offset, len(primary), index_encrypted=encrypt_index)
    return data + fdi + primary + footer


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


def _lz4(raw: bytes) -> bytes:
    """LZ4 *block*-format compress (no size prefix), as UE stores compression blocks."""
    import lz4.block
    return lz4.block.compress(raw, store_size=False)
