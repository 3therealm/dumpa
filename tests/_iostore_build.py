"""Hand-rolled UE5 IoStore `.utoc` header encoder for tests.

Not a product module — emits a minimal FIoStoreTocHeader (magic + version + counts +
container flags) so the iostore parser's enumerate-only path can be tested without a real
UE5 cook. Only the header fields the parser reads are populated; the chunk/offset arrays are
not (extraction is deferred).
"""

from __future__ import annotations

import struct
import zlib

from _unrealpak_build import _aes_encrypt, _lz4

_MAGIC = b"-==--==--==--==-"        # 16 bytes

FLAG_COMPRESSED = 1 << 0
FLAG_ENCRYPTED = 1 << 1
FLAG_INDEXED = 1 << 3

_CBS = 0x10000                      # CompressionBlockSize
_NAME_LEN = 32


def build_toc(*, version: int = 3, entry_count: int = 12, compressed_block_count: int = 4,
              name_count: int = 1, name_len: int = 32, flags: int = FLAG_COMPRESSED) -> bytes:
    out = bytearray()
    out += _MAGIC
    out += struct.pack("<B", version)               # 16
    out += struct.pack("<B", 0)                      # 17 reserved0
    out += struct.pack("<H", 0)                      # 18 reserved1
    out += struct.pack("<I", 144)                    # 20 TocHeaderSize
    out += struct.pack("<I", entry_count)            # 24 TocEntryCount
    out += struct.pack("<I", compressed_block_count) # 28
    out += struct.pack("<I", 12)                     # 32 TocCompressedBlockEntrySize
    out += struct.pack("<I", name_count)             # 36 CompressionMethodNameCount
    out += struct.pack("<I", name_len)               # 40 CompressionMethodNameLength
    out += struct.pack("<I", 65536)                  # 44 CompressionBlockSize
    out += struct.pack("<I", 256)                    # 48 DirectoryIndexSize
    out += struct.pack("<I", 1)                      # 52 PartitionCount
    out += struct.pack("<Q", 0xABCD)                 # 56 ContainerId
    out += b"\x00" * 16                              # 64 EncryptionKeyGuid
    out += struct.pack("<B", flags)                  # 80 ContainerFlags
    out += b"\x00" * 63                              # pad to 144
    return bytes(out)


def _fstring(s: str) -> bytes:
    b = s.encode("utf-8") + b"\x00"
    return struct.pack("<i", len(b)) + b


def _toc_header(*, version: int, entry_count: int, block_count: int, name_count: int,
                block_size: int, dir_index_size: int, partition_size: int, flags: int) -> bytes:
    out = bytearray()
    out += _MAGIC                                    # 0
    out += struct.pack("<BBH", version, 0, 0)        # 16 version, reserved0, reserved1
    out += struct.pack("<I", 144)                    # 20 TocHeaderSize
    out += struct.pack("<I", entry_count)            # 24
    out += struct.pack("<I", block_count)            # 28
    out += struct.pack("<I", 12)                     # 32 TocCompressedBlockEntrySize
    out += struct.pack("<I", name_count)             # 36
    out += struct.pack("<I", _NAME_LEN)              # 40 CompressionMethodNameLength
    out += struct.pack("<I", block_size)             # 44 CompressionBlockSize
    out += struct.pack("<I", dir_index_size)         # 48
    out += struct.pack("<I", 1)                      # 52 PartitionCount
    out += struct.pack("<Q", 0xABCD)                 # 56 ContainerId
    out += b"\x00" * 16                              # 64 EncryptionKeyGuid
    out += struct.pack("<I", flags)                  # 80 ContainerFlags (u32)
    out += struct.pack("<I", 0)                      # 84 PerfectHashSeedsCount
    out += struct.pack("<Q", partition_size)         # 88 PartitionSize
    out += struct.pack("<I", 0)                      # 96 ChunksWithoutPerfectHashCount
    out += b"\x00" * 44                              # 100 reserved -> 144
    assert len(out) == 144
    return bytes(out)


def _directory_index(files_with_chunks: list[tuple[str, int]], mount: str) -> bytes:
    """Serialize FIoDirectoryIndexResource (mount + dir tree + file entries + string table)."""
    strings: list[str] = []

    def sid(s: str) -> int:
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    root: dict = {"name": None, "files": [], "children": {}}
    for path, chunk in files_with_chunks:
        parts = [p for p in path.split("/") if p]
        node = root
        for d in parts[:-1]:
            node = node["children"].setdefault(d, {"name": d, "files": [], "children": {}})
        node["files"].append((parts[-1], chunk))

    dir_entries: list[list[int]] = []
    file_entries: list[list[int]] = []
    none = 0xFFFFFFFF

    def add_dir(node: dict) -> int:
        my = len(dir_entries)
        dir_entries.append([none, none, none, none])
        name_idx = none if node["name"] is None else sid(node["name"])
        first_file, prev = none, None
        for fname, chunk in node["files"]:
            fi = len(file_entries)
            file_entries.append([sid(fname), none, chunk])
            if prev is None:
                first_file = fi
            else:
                file_entries[prev][1] = fi
            prev = fi
        child_indices = [add_dir(c) for c in node["children"].values()]
        first_child = child_indices[0] if child_indices else none
        for k in range(1, len(child_indices)):
            dir_entries[child_indices[k - 1]][2] = child_indices[k]
        dir_entries[my] = [name_idx, first_child, none, first_file]
        return my

    add_dir(root)
    blob = _fstring(mount)
    blob += struct.pack("<i", len(dir_entries))
    for e in dir_entries:
        blob += struct.pack("<IIII", *e)
    blob += struct.pack("<i", len(file_entries))
    for e in file_entries:
        blob += struct.pack("<III", *e)
    blob += struct.pack("<i", len(strings))
    for s in strings:
        blob += _fstring(s)
    return blob


def build_iostore(files: dict[str, bytes], *, version: int = 3, compress: str | None = None,
                  encrypt: bool = False, aes_key: bytes | None = None,
                  mount: str = "../../../Game/") -> tuple[bytes, bytes]:
    """Build a complete (.utoc, .ucas) pair: header + chunk/offset/block arrays + method names +
    directory index, with one CBS-aligned chunk (single block) per file. Supports uncompressed,
    zlib, lz4, and oodle (the last stays an undecompressable deferral); optional AES per block +
    directory index."""
    method_table = {None: [], "zlib": ["Zlib"], "lz4": ["LZ4"], "oodle": ["Oodle"]}[compress]
    method_idx = 0 if compress is None else 1

    ucas = bytearray()
    blocks: list[tuple[int, int, int, int]] = []
    chunk_offsets: list[tuple[int, int]] = []
    files_with_chunks: list[tuple[str, int]] = []
    for i, (path, raw) in enumerate(files.items()):
        if compress == "zlib":
            comp = zlib.compress(raw)
        elif compress == "lz4":
            comp = _lz4(raw)
        else:                                        # none / oodle (oodle = raw, never decoded)
            comp = raw
        csize = len(comp)
        stored = _aes_encrypt(comp, aes_key) if (encrypt and aes_key is not None) else comp
        blocks.append((len(ucas), csize, len(raw), method_idx))
        ucas += stored
        chunk_offsets.append((i * _CBS, len(raw)))
        files_with_chunks.append((path, i))

    chunk_ids = b"\x00" * 12 * len(files)
    offset_lengths = b"".join(off.to_bytes(5, "big") + length.to_bytes(5, "big")
                              for off, length in chunk_offsets)
    comp_blocks = b"".join(
        off.to_bytes(5, "little") + csize.to_bytes(3, "little")
        + usize.to_bytes(3, "little") + bytes([midx])
        for off, csize, usize, midx in blocks)
    methods_blob = b"".join(name.encode("ascii").ljust(_NAME_LEN, b"\x00") for name in method_table)

    dir_index = _directory_index(files_with_chunks, mount)
    if encrypt and aes_key is not None:
        dir_index = _aes_encrypt(dir_index, aes_key)

    flags = FLAG_INDEXED
    if compress is not None:
        flags |= FLAG_COMPRESSED
    if encrypt:
        flags |= FLAG_ENCRYPTED

    header = _toc_header(version=version, entry_count=len(files), block_count=len(blocks),
                         name_count=len(method_table), block_size=_CBS,
                         dir_index_size=len(dir_index), partition_size=1 << 40, flags=flags)
    utoc = header + chunk_ids + offset_lengths + comp_blocks + methods_blob + dir_index
    return utoc, bytes(ucas)
