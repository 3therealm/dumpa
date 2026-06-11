"""Hand-rolled DEX encoder for tests: build minimal valid `.dex` bytes.

Not a product module — it lets the DEX-parser and dex-scanner tests synthesize a dex
without shipping a real one. Emits the subset the parser reads: header, string_ids +
string_data, type_ids, field_ids, method_ids, one class_def, its class_data_item, and one
code_item. checksum/signature are left zero (the parser is a reader, not a verifier).

Layout: one class `Lcom/x/A;` (super `Ljava/lang/Object;`) with one instance field `bar`
and one direct method `foo` carrying a code_item, plus a plain string constant "hello".
"""

from __future__ import annotations

import struct


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_dex(*, version: bytes = b"035\x00") -> tuple[bytes, dict]:
    """Return (dex_bytes, info). info has code_off/code_end, cd_off, and str_content."""
    # string pool — indices referenced by type/field/method ids below
    strings = [
        "Lcom/x/A;",            # 0: class descriptor
        "Ljava/lang/Object;",   # 1: super descriptor
        "foo",                  # 2: method name
        "bar",                  # 3: field name
        "I",                    # 4: field type descriptor (primitive)
        "hello",                # 5: a plain string constant (not a descriptor)
    ]
    type_desc_idx = [0, 1, 4]   # type 0=A, 1=Object, 2=I

    n, t, fcount, mcount, ccount = len(strings), len(type_desc_idx), 1, 1, 1
    string_ids_off = 0x70
    type_ids_off = string_ids_off + n * 4
    field_ids_off = type_ids_off + t * 4
    method_ids_off = field_ids_off + fcount * 8
    class_defs_off = method_ids_off + mcount * 8
    data_off = class_defs_off + ccount * 32

    # --- data section: string_data | code_item | class_data ---
    string_data = bytearray()
    string_data_offs: list[int] = []
    str_content: dict[str, tuple[int, int]] = {}
    for s in strings:
        raw = s.encode("utf-8")
        string_data_offs.append(data_off + len(string_data))
        string_data += _uleb(len(s))
        content_start = data_off + len(string_data)
        string_data += raw + b"\x00"
        str_content[s] = (content_start, content_start + len(raw))

    code_off = data_off + len(string_data)
    insns = b"\x00\x01\x02\x03"          # 2 u16 code units
    code_item = struct.pack("<HHHHII", 1, 1, 0, 0, 0, len(insns) // 2) + insns
    code_end = code_off + len(code_item)

    cd_off = code_end
    class_data = (_uleb(0) + _uleb(1) + _uleb(1) + _uleb(0)        # static/inst/direct/virtual
                  + _uleb(0) + _uleb(2)                            # instance field: diff0, access
                  + _uleb(0) + _uleb(1) + _uleb(code_off))         # direct method: diff0, access, code_off
    data_section = bytes(string_data) + code_item + class_data

    string_ids = struct.pack("<" + "I" * n, *string_data_offs)
    type_ids = struct.pack("<" + "I" * t, *type_desc_idx)
    field_ids = struct.pack("<HHI", 0, 2, 3)                       # class A, type I, name "bar"
    method_ids = struct.pack("<HHI", 0, 0, 2)                      # class A, proto 0, name "foo"
    class_def = struct.pack("<IIIIIIII", 0, 1, 1, 0, 0xFFFFFFFF, 0, cd_off, 0)

    body = string_ids + type_ids + field_ids + method_ids + class_def + data_section
    file_size = 0x70 + len(body)

    header = bytearray(b"dex\n" + version)
    header += b"\x00" * 4                                          # checksum
    header += b"\x00" * 20                                         # signature
    header += struct.pack("<I", file_size)
    header += struct.pack("<I", 0x70)                              # header_size
    header += struct.pack("<I", 0x12345678)                       # endian_tag
    header += struct.pack("<II", 0, 0)                            # link_size, link_off
    header += struct.pack("<I", 0)                                # map_off
    header += struct.pack("<II", n, string_ids_off)
    header += struct.pack("<II", t, type_ids_off)
    header += struct.pack("<II", 0, 0)                            # proto_ids
    header += struct.pack("<II", fcount, field_ids_off)
    header += struct.pack("<II", mcount, method_ids_off)
    header += struct.pack("<II", ccount, class_defs_off)
    header += struct.pack("<II", len(data_section), data_off)
    assert len(header) == 0x70

    out = bytes(header) + body
    assert len(out) == file_size
    info = {"code_off": code_off, "code_end": code_end, "cd_off": cd_off,
            "str_content": str_content}
    return out, info
