"""Hand-rolled `resources.arsc` encoder for tests.

Not a product module — it synthesizes a minimal binary resource table (one package, a
global value pool, a type pool, a key pool, and dense string entries) so the ARSC parser
can be tested without shipping a real apk. Mirrors only the subset the decoder reads.

References: AOSP `ResourceTypes.h` (ResTable_header / _package / _type / _entry, Res_value).
"""

from __future__ import annotations

import struct

_RES_VALUE_STRING = 0x03
_ENTRY_FLAG_COMPLEX = 0x0001
_TYPE_FLAG_SPARSE = 0x01
_TYPE_FLAG_OFFSET16 = 0x02


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


def _config_bytes(language: bytes = b"", country: bytes = b"", density: int = 0) -> bytes:
    """A ResTable_config: the minimal 8-byte default, or a 16-byte locale/density variant."""
    if not (language or country or density):
        return struct.pack("<I", 8) + b"\x00" * 4              # size word + pad (default)
    lang = (language + b"\x00\x00")[:2]
    cc = (country + b"\x00\x00")[:2]
    return (struct.pack("<I", 16) + b"\x00" * 4                # size + imsi(mcc/mnc)
            + lang + cc                                        # locale: language[2] + country[2]
            + struct.pack("<BBH", 0, 0, density))              # orientation, touchscreen, density


def _entry_blob(entries: list[tuple[int, int]]) -> tuple[list[int], bytes]:
    """Dense entry payload: each (key_index, global_value_index) -> entry + string Res_value."""
    offsets: list[int] = []
    blob = bytearray()
    for key_idx, gval_idx in entries:
        offsets.append(len(blob))
        blob += struct.pack("<HHI", 8, 0, key_idx)                       # ResTable_entry
        blob += struct.pack("<HBBI", 8, 0, _RES_VALUE_STRING, gval_idx)  # Res_value (string)
    return offsets, bytes(blob)


def _type_header(type_id: int, flags: int, entry_count: int, entries_start: int,
                 size: int, config: bytes) -> bytes:
    header_size = 20 + len(config)
    return (struct.pack("<HHI", 0x0201, header_size, size)
            + struct.pack("<BBHII", type_id, flags, 0, entry_count, entries_start)
            + config)


def _type_chunk(type_id: int, entries: list[tuple[int, int]], config: bytes | None = None) -> bytes:
    """A dense ResTable_type; entries = list of (key_index, global_value_index)."""
    config = _config_bytes() if config is None else config
    offsets, blob = _entry_blob(entries)
    off_blob = b"".join(struct.pack("<I", o) for o in offsets)
    entries_start = 20 + len(config) + len(off_blob)
    return (_type_header(type_id, 0, len(entries), entries_start, entries_start + len(blob), config)
            + off_blob + blob)


def _type_chunk_offset16(type_id: int, entries: list[tuple[int, int]],
                         config: bytes | None = None) -> bytes:
    """A ResTable_type with FLAG_OFFSET16: u16 offsets (offset/4), `0xFFFF` for absent."""
    config = _config_bytes() if config is None else config
    offsets, blob = _entry_blob(entries)
    off_blob = b"".join(struct.pack("<H", o // 4) for o in offsets)
    while len(off_blob) % 4:                                   # keep entries 4-byte aligned
        off_blob += b"\x00\x00"
    entries_start = 20 + len(config) + len(off_blob)
    return (_type_header(type_id, _TYPE_FLAG_OFFSET16, len(entries), entries_start,
                         entries_start + len(blob), config) + off_blob + blob)


def _type_chunk_sparse(type_id: int, entries: list[tuple[int, int]],
                       config: bytes | None = None) -> bytes:
    """A ResTable_type with FLAG_SPARSE: (idx u16, offset/4 u16) records, present only."""
    config = _config_bytes() if config is None else config
    offsets, blob = _entry_blob(entries)
    off_blob = b"".join(struct.pack("<HH", i, o // 4) for i, o in enumerate(offsets))
    entries_start = 20 + len(config) + len(off_blob)
    return (_type_header(type_id, _TYPE_FLAG_SPARSE, len(entries), entries_start,
                         entries_start + len(blob), config) + off_blob + blob)


def _bag_type_chunk(type_id: int, key_idx: int, gval_indices: list[int],
                    config: bytes | None = None) -> bytes:
    """A ResTable_type with one complex (string-array) entry holding `gval_indices` values."""
    config = _config_bytes() if config is None else config
    count = len(gval_indices)
    entry = struct.pack("<HHI", 16, _ENTRY_FLAG_COMPLEX, key_idx)   # ResTable_map_entry header
    entry += struct.pack("<II", 0, count)                           # parent, count
    for gi in gval_indices:
        entry += struct.pack("<I", 0x01000000 | type_id)           # ResTable_ref name (arbitrary)
        entry += struct.pack("<HBBI", 8, 0, _RES_VALUE_STRING, gi)  # Res_value (string)
    entries_start = 20 + len(config) + 4                            # one u32 offset
    return (_type_header(type_id, 0, 1, entries_start, entries_start + len(entry), config)
            + struct.pack("<I", 0) + entry)


def _pack_table(package_name: str, type_names: list[str], values: list[str],
                keys: list[str], type_chunks: list[bytes]) -> bytes:
    """Assemble a one-package resources.arsc from prebuilt pools + type chunks."""
    global_pool = _utf8_pool(values)
    type_pool = _utf8_pool(type_names)
    key_pool = _utf8_pool(keys)

    name_u16 = package_name.encode("utf-16-le")
    name_field = name_u16 + b"\x00" * (256 - len(name_u16))
    pkg_header_size = 8 + 4 + 256 + 16                       # = 284
    type_strings_off = pkg_header_size
    key_strings_off = pkg_header_size + len(type_pool)
    pkg_body = type_pool + key_pool + b"".join(type_chunks)
    pkg_size = pkg_header_size + len(pkg_body)
    pkg = (struct.pack("<HHI", 0x0200, pkg_header_size, pkg_size)
           + struct.pack("<I", 0x7F)
           + name_field
           + struct.pack("<IIII", type_strings_off, 0, key_strings_off, 0)
           + pkg_body)

    table_header_size = 12
    table_size = table_header_size + len(global_pool) + len(pkg)
    return (struct.pack("<HHI", 0x0002, table_header_size, table_size)
            + struct.pack("<I", 1)
            + global_pool + pkg)


def build_arsc(package_name: str, type_name: str,
               entries: list[tuple[str, str]]) -> bytes:
    """Build a one-package resources.arsc.

    entries: (resource_name, string_value) pairs, all of type `type_name` (e.g. "string").
    """
    values = [v for _, v in entries]
    keys = [name for name, _ in entries]
    type_chunk = _type_chunk(1, [(i, i) for i in range(len(entries))])
    return _pack_table(package_name, [type_name], values, keys, [type_chunk])


def build_arsc_encoded(package_name: str, type_name: str,
                       entries: list[tuple[str, str]], kind: str) -> bytes:
    """Like `build_arsc` but encode the single type chunk as 'dense'|'offset16'|'sparse'."""
    values = [v for _, v in entries]
    keys = [name for name, _ in entries]
    pairs = [(i, i) for i in range(len(entries))]
    encoder = {"dense": _type_chunk, "offset16": _type_chunk_offset16,
               "sparse": _type_chunk_sparse}[kind]
    return _pack_table(package_name, [type_name], values, keys, [encoder(1, pairs)])


def build_arsc_bag(package_name: str, type_name: str, name: str, values: list[str]) -> bytes:
    """One-package table whose single entry is a complex string-array named `name`."""
    return _pack_table(package_name, [type_name], values, [name],
                       [_bag_type_chunk(1, 0, list(range(len(values))))])


def build_arsc_localized(package_name: str, type_name: str, name: str, default_value: str,
                         variant_value: str, language: bytes, country: bytes) -> bytes:
    """Two type chunks for one entry: a default config plus a locale variant."""
    return _pack_table(
        package_name, [type_name], [default_value, variant_value], [name],
        [_type_chunk(1, [(0, 0)]),
         _type_chunk(1, [(0, 1)], config=_config_bytes(language=language, country=country))])
