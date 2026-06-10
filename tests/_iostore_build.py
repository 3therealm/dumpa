"""Hand-rolled UE5 IoStore `.utoc` header encoder for tests.

Not a product module — emits a minimal FIoStoreTocHeader (magic + version + counts +
container flags) so the iostore parser's enumerate-only path can be tested without a real
UE5 cook. Only the header fields the parser reads are populated; the chunk/offset arrays are
not (extraction is deferred).
"""

from __future__ import annotations

import struct

_MAGIC = b"-==--==--==--==-"        # 16 bytes

FLAG_COMPRESSED = 1 << 0
FLAG_ENCRYPTED = 1 << 1
FLAG_INDEXED = 1 << 3


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
