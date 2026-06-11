"""Shared AOSP resource-chunk primitives: little-endian scalar reads + the string pool.

Both `core.axml` (binary AndroidManifest.xml) and `core.arsc` (binary resources.arsc)
are streams of the same typed chunks defined in AOSP `ResourceTypes.h`, and both embed
the identical `ResStringPool` format (a UTF-8 *or* UTF-16-LE pool with 1/2-byte length
prefixes). This module owns that shared machinery — one implementation of the fiddly
length+encoding decode — so neither parser carries its own copy.

Reads are bounds-checked and raise `ResChunkError`; each parser catches it at its own
boundary and re-raises its format-specific error, so `parse_axml` only ever emits
`AxmlError` and `parse_arsc` only `ArscError`.
"""

from __future__ import annotations

import struct

from dumpa.core.errors import ResChunkError

# String pool flags (ResStringPool_header.flags).
UTF8_FLAG = 1 << 8


def u16(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        raise ResChunkError(f"truncated u16 at offset {off}")
    return int(struct.unpack_from("<H", data, off)[0])


def u32(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        raise ResChunkError(f"truncated u32 at offset {off}")
    return int(struct.unpack_from("<I", data, off)[0])


def _utf8_len(data: bytes, pos: int) -> tuple[int, int]:
    """Decode a UTF-8 string-pool length (1 or 2 bytes); return (length, next_pos)."""
    if pos >= len(data):
        raise ResChunkError("truncated UTF-8 length")
    value = data[pos]
    pos += 1
    if value & 0x80:
        if pos >= len(data):
            raise ResChunkError("truncated UTF-8 length (2-byte)")
        value = ((value & 0x7F) << 8) | data[pos]
        pos += 1
    return value, pos


def _decode_at(data: bytes, pos: int, is_utf8: bool) -> tuple[str, int, int]:
    """Decode one pooled string; return (value, content_start, content_end).

    The span is the absolute byte range of the *character bytes* (after the length
    prefix, before any terminator) — what an offset-located finding falls inside.
    Lenient (replace) on bad bytes so a single bad string never aborts a pool.
    """
    if pos < 0 or pos >= len(data):
        return "", pos, pos
    if is_utf8:
        _chars, pos = _utf8_len(data, pos)        # character count (unused; bytes drive it)
        nbytes, pos = _utf8_len(data, pos)
        end = pos + nbytes
        return data[pos:end].decode("utf-8", "replace"), pos, end
    units = u16(data, pos)
    pos += 2
    if units & 0x8000:
        units = ((units & 0x7FFF) << 16) | u16(data, pos)
        pos += 2
    end = pos + units * 2
    return data[pos:end].decode("utf-16-le", "replace"), pos, end


def decode_string(data: bytes, pos: int, is_utf8: bool) -> str:
    """Decode one pooled string at an absolute offset (value only)."""
    return _decode_at(data, pos, is_utf8)[0]


def _pool_header(data: bytes, off: int) -> tuple[int, bool, int, int]:
    """(string_count, is_utf8, offsets_at, data_at) from a RES_STRING_POOL chunk header."""
    if off + 28 > len(data):
        raise ResChunkError("truncated string pool header")
    (_type, header_size, _size, string_count, _style_count,
     flags, strings_start, _styles_start) = struct.unpack_from("<HHIIIIII", data, off)
    return string_count, bool(flags & UTF8_FLAG), off + header_size, off + strings_start


def decode_string_pool(data: bytes, off: int, chunk_size: int) -> list[str]:
    """Decode a RES_STRING_POOL chunk into its list of strings."""
    string_count, is_utf8, offsets_at, data_at = _pool_header(data, off)
    chunk_end = off + chunk_size
    strings: list[str] = []
    for i in range(string_count):
        pos = data_at + u32(data, offsets_at + i * 4)
        if pos >= chunk_end:
            strings.append("")
            continue
        strings.append(decode_string(data, pos, is_utf8))
    return strings


def decode_string_pool_with_spans(
    data: bytes, off: int, chunk_size: int,
) -> tuple[list[str], list[tuple[int, int]]]:
    """Like `decode_string_pool`, but also return each string's absolute (start, end) byte span.

    The spans let an offset-located finding (a URL a content scanner matched inside
    `resources.arsc`) be attributed to the pooled string that owns that byte range.
    """
    string_count, is_utf8, offsets_at, data_at = _pool_header(data, off)
    chunk_end = off + chunk_size
    strings: list[str] = []
    spans: list[tuple[int, int]] = []
    for i in range(string_count):
        pos = data_at + u32(data, offsets_at + i * 4)
        if pos >= chunk_end:
            strings.append("")
            spans.append((0, 0))
            continue
        value, start, end = _decode_at(data, pos, is_utf8)
        strings.append(value)
        spans.append((start, end))
    return strings, spans
