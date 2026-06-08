"""Zero-dependency binary AndroidManifest.xml (AXML) decoder.

Android ships `AndroidManifest.xml` inside an apk as a compiled binary resource chunk,
not text. This module decodes that format with the stdlib alone (`struct`) into a thin
element tree — matching the toolkit's no-extra-deps ethos (same stack as `core.config`,
`core.rules`). It is deliberately structure-only: `core.manifest` maps the tree into the
manifest-specific `ManifestInfo`.

The format is a sequence of typed chunks: a wrapping XML chunk, a string pool, an
optional resource map (attribute-name resolution for stripped names), then a stream of
start/end element and namespace nodes. Every read is bounds-checked; any inconsistency
raises `AxmlError` so callers degrade to "no manifest facts", never crash.

References: AOSP `ResourceTypes.h` (ResChunk_header, ResStringPool_header,
ResXMLTree_node / _attrExt / _attribute, Res_value).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from dumpa.core.errors import AxmlError

# Chunk types (ResChunk_header.type).
_RES_STRING_POOL = 0x0001
_RES_XML = 0x0003
_RES_XML_START_NAMESPACE = 0x0100
_RES_XML_END_NAMESPACE = 0x0101
_RES_XML_START_ELEMENT = 0x0102
_RES_XML_END_ELEMENT = 0x0103
_RES_XML_CDATA = 0x0104
_RES_XML_RESOURCE_MAP = 0x0180

# String pool flags.
_UTF8_FLAG = 1 << 8

# Res_value.dataType values we interpret.
_TYPE_REFERENCE = 0x01
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12

# strref sentinel ("no string").
_NO_ENTRY = 0xFFFFFFFF

# Defensive caps so pathological input cannot exhaust memory / recurse forever.
_MAX_ELEMENTS = 100_000
_MAX_DEPTH = 256

# Resource IDs for the handful of framework attributes we resolve by id when an
# attribute's name string was stripped (some build tools drop names, keep only ids).
_RESID_TO_ATTR: dict[int, str] = {
    0x01010003: "name",
    0x01010006: "permission",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010018: "authorities",
    0x01010027: "scheme",
    0x01010028: "host",
    0x01010029: "port",
    0x0101002A: "path",
    0x0101002B: "pathPrefix",
    0x0101002C: "pathPattern",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010280: "allowBackup",
    0x010104EE: "autoVerify",
}

# AttrValue is what a decoded attribute carries: a bool for INT_BOOLEAN, else a string.
AttrValue = str | bool


@dataclass
class AxmlElement:
    """One element in the decoded tree. `attrs` is keyed by local attribute name."""
    tag: str
    attrs: dict[str, AttrValue] = field(default_factory=dict)
    children: list[AxmlElement] = field(default_factory=list)

    def iter(self) -> list[AxmlElement]:
        """Depth-first list of this element and all descendants."""
        out = [self]
        for child in self.children:
            out.extend(child.iter())
        return out


@dataclass
class AxmlDocument:
    """A decoded AXML file: its root element (typically `<manifest>`)."""
    root: AxmlElement | None


def _u16(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        raise AxmlError(f"truncated u16 at offset {off}")
    return int(struct.unpack_from("<H", data, off)[0])


def _u32(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        raise AxmlError(f"truncated u32 at offset {off}")
    return int(struct.unpack_from("<I", data, off)[0])


def _utf8_len(data: bytes, pos: int) -> tuple[int, int]:
    """Decode a UTF-8 string-pool length (1 or 2 bytes); return (length, next_pos)."""
    if pos >= len(data):
        raise AxmlError("truncated UTF-8 length")
    value = data[pos]
    pos += 1
    if value & 0x80:
        if pos >= len(data):
            raise AxmlError("truncated UTF-8 length (2-byte)")
        value = ((value & 0x7F) << 8) | data[pos]
        pos += 1
    return value, pos


def _decode_string(data: bytes, pos: int, is_utf8: bool) -> str:
    """Decode one pooled string at an absolute offset; lenient (replace) on bad bytes."""
    if pos < 0 or pos >= len(data):
        return ""
    if is_utf8:
        _chars, pos = _utf8_len(data, pos)        # character count (unused; bytes drive it)
        nbytes, pos = _utf8_len(data, pos)
        return data[pos:pos + nbytes].decode("utf-8", "replace")
    units = _u16(data, pos)
    pos += 2
    if units & 0x8000:
        units = ((units & 0x7FFF) << 16) | _u16(data, pos)
        pos += 2
    return data[pos:pos + units * 2].decode("utf-16-le", "replace")


def _parse_string_pool(data: bytes, off: int, chunk_size: int) -> list[str]:
    """Decode a RES_STRING_POOL chunk into its list of strings."""
    if off + 28 > len(data):
        raise AxmlError("truncated string pool header")
    _type, header_size, _size, string_count, _style_count, flags, strings_start, _styles_start = (
        struct.unpack_from("<HHIIIIII", data, off)
    )
    is_utf8 = bool(flags & _UTF8_FLAG)
    offsets_at = off + header_size
    data_at = off + strings_start
    chunk_end = off + chunk_size
    strings: list[str] = []
    for i in range(string_count):
        rel = _u32(data, offsets_at + i * 4)
        pos = data_at + rel
        if pos >= chunk_end:
            strings.append("")
            continue
        strings.append(_decode_string(data, pos, is_utf8))
    return strings


def _parse_resource_map(data: bytes, off: int, chunk_size: int) -> list[int]:
    """Decode a RES_XML_RESOURCE_MAP chunk into resource-id-per-string-index."""
    header_size = _u16(data, off + 2)
    count = max(0, (chunk_size - header_size) // 4)
    base = off + header_size
    return [_u32(data, base + i * 4) for i in range(count) if base + i * 4 + 4 <= len(data)]


def _string(pool: list[str], ref: int) -> str:
    """Resolve a string-pool reference; "" for the no-entry sentinel or out-of-range."""
    if ref == _NO_ENTRY or ref < 0 or ref >= len(pool):
        return ""
    return pool[ref]


def _attr_name(pool: list[str], resmap: list[int], name_ref: int) -> str:
    """Resolve an attribute name, falling back to the resource map when the name is stripped."""
    name = _string(pool, name_ref)
    if name:
        return name
    if 0 <= name_ref < len(resmap):
        return _RESID_TO_ATTR.get(resmap[name_ref], "")
    return ""


def _decode_value(pool: list[str], raw_ref: int, data_type: int, data_val: int) -> AttrValue:
    """Resolve an attribute's value from its raw string ref or typed Res_value."""
    if raw_ref != _NO_ENTRY:
        return _string(pool, raw_ref)
    if data_type == _TYPE_STRING:
        return _string(pool, data_val)
    if data_type == _TYPE_INT_BOOLEAN:
        return data_val != 0
    if data_type in (_TYPE_INT_DEC, _TYPE_INT_HEX):
        return str(data_val)
    if data_type == _TYPE_REFERENCE:
        return f"@{data_val:08x}"
    return str(data_val)


def _parse_start_element(data: bytes, off: int, pool: list[str], resmap: list[int]) -> AxmlElement:
    """Decode a RES_XML_START_ELEMENT node into an AxmlElement (tag + attrs, no children)."""
    # Node header is 16 bytes (ResChunk_header + lineNumber + comment); attrExt follows.
    ext = off + 16
    name_ref = _u32(data, ext + 4)
    attr_start = _u16(data, ext + 8)
    attr_size = _u16(data, ext + 10)
    attr_count = _u16(data, ext + 12)
    tag = _string(pool, name_ref)
    element = AxmlElement(tag=tag)
    attrs_at = ext + attr_start
    for i in range(attr_count):
        a = attrs_at + i * attr_size
        if a + 20 > len(data):
            break
        name_idx = _u32(data, a + 4)
        raw_ref = _u32(data, a + 8)
        data_type = data[a + 15]
        data_val = _u32(data, a + 16)
        name = _attr_name(pool, resmap, name_idx)
        if not name:
            continue
        element.attrs[name] = _decode_value(pool, raw_ref, data_type, data_val)
    return element


def parse_axml(data: bytes) -> AxmlDocument:
    """Decode binary AXML bytes into an AxmlDocument. Raise AxmlError on malformed input."""
    if len(data) < 8:
        raise AxmlError("file too small to be AXML")
    file_type, file_header, file_size = struct.unpack_from("<HHI", data, 0)
    if file_type != _RES_XML:
        raise AxmlError(f"not an AXML file (chunk type 0x{file_type:04x})")

    pool: list[str] = []
    resmap: list[int] = []
    root: AxmlElement | None = None
    stack: list[AxmlElement] = []
    element_count = 0

    off = file_header if file_header >= 8 else 8
    end = min(file_size, len(data)) if file_size else len(data)
    while off + 8 <= end:
        chunk_type = _u16(data, off)
        chunk_size = _u32(data, off + 4)
        if chunk_size < 8 or off + chunk_size > len(data):
            raise AxmlError(f"bad chunk size {chunk_size} at offset {off}")

        if chunk_type == _RES_STRING_POOL:
            pool = _parse_string_pool(data, off, chunk_size)
        elif chunk_type == _RES_XML_RESOURCE_MAP:
            resmap = _parse_resource_map(data, off, chunk_size)
        elif chunk_type == _RES_XML_START_ELEMENT:
            element_count += 1
            if element_count > _MAX_ELEMENTS:
                raise AxmlError("element count exceeds limit")
            if len(stack) > _MAX_DEPTH:
                raise AxmlError("element nesting exceeds limit")
            element = _parse_start_element(data, off, pool, resmap)
            if stack:
                stack[-1].children.append(element)
            elif root is None:
                root = element
            stack.append(element)
        elif chunk_type == _RES_XML_END_ELEMENT and stack:
            stack.pop()
        # namespace + cdata nodes carry no structure we need; skip by advancing.

        off += chunk_size

    return AxmlDocument(root=root)
