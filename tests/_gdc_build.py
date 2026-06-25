"""Hand-rolled Godot `.gdc` token-buffer encoder for tests.

Not a product module — it lets the core.gdc and godot-scanner tests synthesize GDScript
token buffers (Godot 3.x byte-identifier layout and uncompressed Godot 4.x UTF-32 layout)
with chosen identifiers + string/int constants, without shipping a real compiled script.
"""

from __future__ import annotations

import struct

_MAGIC = b"GDSC"
_XOR = 0xB6


def str_variant(value: str) -> bytes:
    raw = value.encode("utf-8")
    pad = (-len(raw)) % 4
    return struct.pack("<II", 4, len(raw)) + raw + b"\x00" * pad


def int_variant(value: int) -> bytes:
    return struct.pack("<Ii", 2, value)             # type INT (2), 32-bit payload


def build_gdc_v3(identifiers: list[str], constants: list[bytes], *, version: int = 13) -> bytes:
    buf = _MAGIC + struct.pack("<IIIII", version, len(identifiers), len(constants), 0, 0)
    for name in identifiers:
        raw = name.encode("utf-8") + b"\x00"
        raw += b"\x00" * ((-len(raw)) % 4)      # Godot 3 pads the stored length to 4 bytes
        buf += struct.pack("<I", len(raw)) + bytes(b ^ _XOR for b in raw)
    return buf + b"".join(constants)


def build_gdc_v4(identifiers: list[str], constants: list[bytes], *, version: int = 101) -> bytes:
    header_len = 20 if version == 100 else 16   # v100 (4.3/4.4) body header is 20 bytes
    body = struct.pack("<II", len(identifiers), len(constants)) + b"\x00" * (header_len - 8)
    for name in identifiers:
        cps = [ord(c) for c in name]                # length stored without a NUL terminator
        body += struct.pack("<I", len(cps))
        body += b"".join(bytes(b ^ _XOR for b in struct.pack("<I", cp)) for cp in cps)
    body += b"".join(constants)
    return _MAGIC + struct.pack("<II", version, 0) + body   # decompressed_size 0 = uncompressed
