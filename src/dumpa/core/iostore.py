"""Zero-dependency Unreal Engine 5 IoStore TOC (`.utoc`) reader — enumerate only.

UE5 ships cooked content in the IoStore container: a `.utoc` table-of-contents plus a
`.ucas` data blob. The TOC header (`FIoStoreTocHeader`, magic `-==--==--==--==-`) records
the chunk count, compression block layout, compression-method name table, directory-index
size, and container flags (compressed / encrypted / signed / indexed).

This reads the header to **report** what a container holds — version, chunk count,
compression methods, and the encrypted/compressed flags — but does **not** extract chunk
data. UE5 IoStore chunks are almost always Oodle-compressed and frequently AES-encrypted;
neither codec is in the stdlib, so extraction is deferred (a documented `dumpa[unreal]`
extra would supply them). `extract()` is a stub returning 0, kept for signature parity with
`core.unrealpak`.

Every read is bounds-checked; a truncated/foreign file parses to None rather than over-reading.

Reference: Unreal `IO/IoStore.h` (`FIoStoreTocHeader`, `EIoContainerFlags`).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

const_magic = b"-==--==--==--==-"      # 16 bytes

# EIoContainerFlags bitmask.
_FLAG_COMPRESSED = 1 << 0
_FLAG_ENCRYPTED = 1 << 1
_FLAG_SIGNED = 1 << 2
_FLAG_INDEXED = 1 << 3

_MAX_NAMES = 64
_MAX_NAME_LEN = 256


@dataclass(frozen=True)
class Toc:
    version: int
    entry_count: int                    # TocEntryCount (chunks)
    compressed_block_count: int
    compression_methods: list[str]
    directory_index_size: int
    flags: int
    encrypted: bool
    compressed: bool
    indexed: bool


def parse_toc(path: Path) -> Toc | None:
    """Parse the FIoStoreTocHeader at the start of a `.utoc`. Enumerate-only."""
    try:
        with path.open("rb") as f:
            head = f.read(144)              # header is < 144 bytes across the v1-5 range
    except OSError:
        return None
    if len(head) < 64 or head[:16] != const_magic:
        return None

    # Layout after the 16-byte magic (little-endian):
    #   u8  Version
    #   u8  Reserved0
    #   u16 Reserved1
    #   u32 TocHeaderSize
    #   u32 TocEntryCount
    #   u32 TocCompressedBlockEntryCount
    #   u32 TocCompressedBlockEntrySize
    #   u32 CompressionMethodNameCount
    #   u32 CompressionMethodNameLength
    #   u32 CompressionBlockSize
    #   u32 DirectoryIndexSize
    #   u32 PartitionCount
    #   u64 ContainerId
    #   FGuid EncryptionKeyGuid (16)
    #   u8  ContainerFlags
    try:
        version = head[16]
        (entry_count, comp_block_count, _comp_block_size,
         name_count, name_len, _block_size, dir_index_size) = struct.unpack_from(
            "<IIIIIII", head, 24)
    except struct.error:
        return None
    # ContainerFlags sits after PartitionCount(u32) + ContainerId(u64) + EncryptionKeyGuid(16).
    flags_off = 24 + 7 * 4 + 4 + 8 + 16
    flags = head[flags_off] if flags_off < len(head) else 0

    # The compression-method name table sits after the chunk/offset/block arrays, whose sizes
    # we do not compute (enumerate-only); record the declared count, not the names themselves.
    methods = [f"<{name_count} method name(s), {name_len}B each>"] if name_count else []
    return Toc(
        version=version, entry_count=entry_count, compressed_block_count=comp_block_count,
        compression_methods=methods, directory_index_size=dir_index_size, flags=flags,
        encrypted=bool(flags & _FLAG_ENCRYPTED), compressed=bool(flags & _FLAG_COMPRESSED),
        indexed=bool(flags & _FLAG_INDEXED))


def extract(path: Path, toc: Toc, out_dir: Path) -> int:
    """Deferred: IoStore chunk extraction needs Oodle/AES (not in the stdlib). Always 0."""
    return 0
