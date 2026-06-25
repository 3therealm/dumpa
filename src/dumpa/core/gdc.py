"""Zero-dependency Godot GDScript token-buffer (`.gdc`) string extractor.

A `.gdc` file is the compiled token buffer for a GDScript source — a `GDSC` header, an
identifier table, a constant table (marshalled Variants), then the token/line streams. This
is **not** a decompiler: it does not reconstruct control flow or source. It decodes only the
identifier table and the string-typed constants so the Godot scanner can mine endpoints +
secrets out of them (URLs, API keys, etc. live in the constant pool).

Two layouts are handled:

* Godot 3.x (bytecode version <= 13): header `magic | version | id_count | const_count |
  line_count | token_count`; identifiers are `len u32` + `len` bytes XORed with 0xB6;
  constants are little-endian marshalled Variants.
* Godot 4.x (tokenizer version 100 or 101): header `magic | version | decompressed_size`; when
  `decompressed_size != 0` the body is Zstd-compressed (deferred — no stdlib Zstd). The
  decompressed body starts with `id_count | const_count` then a version-dependent run of fields
  (a 20-byte body header for v100 — Godot 4.3/4.4, a 16-byte one for v101 — Godot 4.5); identifiers
  are `len u32` codepoints, each a little-endian u32 whose four bytes are individually XORed
  with 0xB6 (UTF-32); constants are Variants.

Everything is bounds-checked and fail-soft: an unknown version, a Zstd body, a malformed
Variant, or truncation yields a partial/empty result, never an exception.

References: Godot `modules/gdscript/gdscript_tokenizer_buffer.cpp` and `core/io/marshalls.cpp`
(`decode_variant`).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

const_magic = b"GDSC"
_XOR = 0xB6
_GODOT3_MAX_VERSION = 13            # Godot 3 rejects bytecode versions above this
_GODOT4_TOKENIZER_VERSIONS = frozenset({100, 101})  # 100: Godot 4.3/4.4, 101: Godot 4.5
_GODOT4_MIN_VERSION = 100           # Godot-4-era boundary (flag only; not a parse gate)
_MAX_COUNT = 100_000                # hard cap on identifier/constant table counts (anti-DoS)
_MAX_STRINGS = 50_000               # hard cap on collected strings (anti-DoS)
_MAX_STR_BYTES = 1 << 20

# Variant type ids (low byte of the marshalled header). Shared 0-4 between Godot 3 and 4.
_VT_NIL = 0
_VT_BOOL = 1
_VT_INT = 2
_VT_FLOAT = 3
_VT_STRING = 4
_VT_STRING_NAME = 21        # Godot 4 only
_ENCODE_FLAG_64 = 1 << 16


@dataclass
class GdcInfo:
    version: int
    godot4: bool
    compressed: bool                        # Godot 4 Zstd body we cannot decode (deferred)
    strings: list[str] = field(default_factory=list)    # identifiers + string constants


def _u32(data: bytes, pos: int) -> int:
    return int(struct.unpack_from("<I", data, pos)[0])


def parse(data: bytes) -> GdcInfo | None:
    """Parse a `.gdc` buffer; return identifiers + string constants, or None if not a GDSC."""
    if len(data) < 12 or data[:4] != const_magic:
        return None
    version = _u32(data, 4)
    if version <= _GODOT3_MAX_VERSION:
        return _parse_godot3(data, version)
    if version in _GODOT4_TOKENIZER_VERSIONS:
        return _parse_godot4(data, version)
    # 14..99 / 102+ : Godot rejects these outright — surface the header, decode nothing.
    return GdcInfo(version=version, godot4=version >= _GODOT4_MIN_VERSION, compressed=False)


def _parse_godot3(data: bytes, version: int) -> GdcInfo:
    info = GdcInfo(version=version, godot4=False, compressed=False)
    if len(data) < 24:
        return info
    id_count = _u32(data, 8)
    const_count = _u32(data, 12)
    pos = 24                                # skip line_count + token_count
    pos = _read_ids(data, pos, id_count, info, godot4=False)
    if pos < 0:
        return info
    _read_constants(data, pos, const_count, info, godot4=False)
    return info


def _parse_godot4(data: bytes, version: int) -> GdcInfo:
    decompressed_size = _u32(data, 8)
    if decompressed_size != 0:
        # Zstd-compressed body — no stdlib decompressor; surface the header, defer the strings.
        return GdcInfo(version=version, godot4=True, compressed=True)
    info = GdcInfo(version=version, godot4=True, compressed=False)
    body = data[12:]
    header_len = 20 if version == 100 else 16   # v100 (4.3/4.4) carries one extra field
    if len(body) < header_len:
        return info
    id_count = _u32(body, 0)
    const_count = _u32(body, 4)
    pos = header_len                        # skip the remaining body-header fields
    pos = _read_ids(body, pos, id_count, info, godot4=True)
    if pos < 0:
        return info
    _read_constants(body, pos, const_count, info, godot4=True)
    return info


def _add_string(info: GdcInfo, s: str) -> bool:
    """Collect a non-empty string; return False once the string cap is reached (caller stops)."""
    if len(info.strings) >= _MAX_STRINGS:
        return False
    if s:
        info.strings.append(s)
    return True


def _read_ids(data: bytes, pos: int, count: int, info: GdcInfo, *, godot4: bool) -> int:
    """Read the identifier table; return the position after it, or -1 on malformed input."""
    if count < 0 or count > _MAX_COUNT:
        return -1
    for _ in range(count):
        if pos + 4 > len(data):
            return -1
        length = _u32(data, pos)
        pos += 4
        if godot4:
            nbytes = length * 4
            if length > _MAX_STR_BYTES or pos + nbytes > len(data):
                return -1
            chars: list[str] = []
            for j in range(length):
                raw = data[pos + j * 4:pos + (j + 1) * 4]
                cp = struct.unpack("<I", bytes(b ^ _XOR for b in raw))[0]
                if cp == 0:
                    break
                if cp <= 0x10FFFF:
                    chars.append(chr(cp))
            pos += nbytes
            if not _add_string(info, "".join(chars)):
                return pos
        else:
            if length > _MAX_STR_BYTES or pos + length > len(data):
                return -1
            raw = bytes(b ^ _XOR for b in data[pos:pos + length])
            pos += length
            if not _add_string(info, raw.split(b"\x00", 1)[0].decode("utf-8", "replace")):
                return pos
    return pos


def _read_constants(data: bytes, pos: int, count: int, info: GdcInfo, *, godot4: bool) -> None:
    """Read the constant pool, collecting string values; stop at the first undecodable Variant."""
    if count < 0 or count > _MAX_COUNT:
        return
    for _ in range(count):
        if len(info.strings) >= _MAX_STRINGS:
            return                          # string cap reached — keep what we have
        pos, value = _decode_variant(data, pos, godot4=godot4)
        if pos < 0:
            return                          # unknown/complex Variant — stop, keep what we have
        if value:
            _add_string(info, value)


def _decode_variant(data: bytes, pos: int, *, godot4: bool) -> tuple[int, str | None]:
    """Decode one marshalled Variant. Returns (next_pos, string_value_or_None); pos<0 on stop."""
    if pos + 4 > len(data):
        return -1, None
    header = _u32(data, pos)
    pos += 4
    vtype = header & 0xFF
    flag64 = bool(header & _ENCODE_FLAG_64)
    if vtype == _VT_NIL:
        return pos, None
    if vtype == _VT_BOOL:
        return (pos + 4, None) if pos + 4 <= len(data) else (-1, None)
    if vtype in (_VT_INT, _VT_FLOAT):
        n = 8 if flag64 else 4
        return (pos + n, None) if pos + n <= len(data) else (-1, None)
    if vtype == _VT_STRING or (godot4 and vtype == _VT_STRING_NAME):
        if pos + 4 > len(data):
            return -1, None
        slen = _u32(data, pos)
        pos += 4
        pad = (4 - (slen % 4)) % 4
        if slen > _MAX_STR_BYTES or pos + slen + pad > len(data):
            return -1, None
        text = data[pos:pos + slen].decode("utf-8", "replace")
        return pos + slen + pad, text
    return -1, None                         # unsupported/complex type — caller stops
