"""Hand-rolled `resources.arsc` encoder for tests.

Not a product module — it synthesizes a minimal binary resource table (one package, a
global value pool, a type pool, a key pool, and dense string entries) so the ARSC parser
can be tested without shipping a real apk. Mirrors only the subset the decoder reads.

References: AOSP `ResourceTypes.h` (ResTable_header / _package / _type / _entry, Res_value).
"""

from __future__ import annotations

import struct

_RES_VALUE_STRING = 0x03


def _utf8_pool(strings: list[str]) -> bytes:
    """Encode a RES_STRING_POOL chunk (UTF-8 flag), matching the decoder's length form."""
    offsets: list[int] = []
    blob = bytearray()
    for s in strings:
        offsets.append(len(blob))
        raw = s.encode("utf-8")
        blob += bytes([len(s), len(raw)]) + raw + b"\x00"      # assumes len < 128
    while len(blob) % 4:
        blob += b"\x00"
    header_size = 28
    offsets_blob = b"".join(struct.pack("<I", o) for o in offsets)
    strings_start = header_size + len(offsets_blob)
    size = strings_start + len(blob)
    header = struct.pack("<HHIIIIII", 0x0001, header_size, size, len(strings), 0,
                         0x100, strings_start, 0)
    return header + offsets_blob + bytes(blob)


def _type_chunk(type_id: int, entries: list[tuple[int, int]]) -> bytes:
    """A dense ResTable_type for `type_id`; entries = list of (key_index, global_value_index)."""
    config = struct.pack("<I", 8) + b"\x00" * 4            # minimal config: size word + pad
    header_size = 8 + 1 + 1 + 2 + 4 + 4 + len(config)      # = 28
    entry_count = len(entries)
    entries_start = header_size + entry_count * 4
    offset_blob = bytearray()
    entry_blob = bytearray()
    for key_idx, gval_idx in entries:
        offset_blob += struct.pack("<I", len(entry_blob))
        entry_blob += struct.pack("<HHI", 8, 0, key_idx)                       # ResTable_entry
        entry_blob += struct.pack("<HBBI", 8, 0, _RES_VALUE_STRING, gval_idx)  # Res_value
    size = entries_start + len(entry_blob)
    header = (struct.pack("<HHI", 0x0201, header_size, size)
              + struct.pack("<BBHII", type_id, 0, 0, entry_count, entries_start)
              + config)
    return header + bytes(offset_blob) + bytes(entry_blob)


def build_arsc(package_name: str, type_name: str,
               entries: list[tuple[str, str]]) -> bytes:
    """Build a one-package resources.arsc.

    entries: (resource_name, string_value) pairs, all of type `type_name` (e.g. "string").
    """
    values = [v for _, v in entries]
    global_pool = _utf8_pool(values)
    type_pool = _utf8_pool([type_name])
    key_pool = _utf8_pool([name for name, _ in entries])
    type_chunk = _type_chunk(1, [(i, i) for i in range(len(entries))])

    name_u16 = package_name.encode("utf-16-le")
    name_field = name_u16 + b"\x00" * (256 - len(name_u16))
    pkg_header_size = 8 + 4 + 256 + 16                       # = 284
    type_strings_off = pkg_header_size
    key_strings_off = pkg_header_size + len(type_pool)
    pkg_body = type_pool + key_pool + type_chunk
    pkg_size = pkg_header_size + len(pkg_body)
    pkg = (struct.pack("<HHI", 0x0200, pkg_header_size, pkg_size)
           + struct.pack("<I", 0x7F)
           + name_field
           + struct.pack("<IIII", type_strings_off, 0, key_strings_off, 0)
           + pkg_body)

    table_header_size = 12
    table_size = table_header_size + len(global_pool) + len(pkg)
    table = (struct.pack("<HHI", 0x0002, table_header_size, table_size)
             + struct.pack("<I", 1)
             + global_pool + pkg)
    return table
