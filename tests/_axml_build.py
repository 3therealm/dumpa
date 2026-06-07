"""Hand-rolled AXML encoder for tests: build binary AndroidManifest.xml bytes.

Not a product module — it exists so manifest/decoder tests can synthesize compiled
manifests without shipping a real apk. Mirrors the subset of the format the decoder
reads (UTF-8 string pool, string + boolean attributes, nested elements).
"""

from __future__ import annotations

import struct

from dumpa.core.axml import AttrValue

_NO_ENTRY = 0xFFFFFFFF
_TYPE_STRING = 0x03
_TYPE_INT_BOOLEAN = 0x12


class _Pool:
    def __init__(self) -> None:
        self._items: list[str] = []
        self._index: dict[str, int] = {}

    def add(self, s: str) -> int:
        if s not in self._index:
            self._index[s] = len(self._items)
            self._items.append(s)
        return self._index[s]

    def encode(self) -> bytes:
        offsets: list[int] = []
        blob = bytearray()
        for s in self._items:
            offsets.append(len(blob))
            raw = s.encode("utf-8")
            blob += bytes([len(s), len(raw)]) + raw + b"\x00"
        while len(blob) % 4:
            blob += b"\x00"
        header_size = 28
        offsets_blob = b"".join(struct.pack("<I", o) for o in offsets)
        strings_start = header_size + len(offsets_blob)
        size = strings_start + len(blob)
        header = struct.pack(
            "<HHIIIIII", 0x0001, header_size, size, len(self._items), 0,
            0x100, strings_start, 0,
        )
        return header + offsets_blob + bytes(blob)


def _start_element(pool: _Pool, tag: str, attrs: dict[str, AttrValue]) -> bytes:
    name_idx = pool.add(tag)
    body = bytearray()
    for key, value in attrs.items():
        key_idx = pool.add(key)
        if isinstance(value, bool):
            raw_ref, dtype, data = _NO_ENTRY, _TYPE_INT_BOOLEAN, (_NO_ENTRY if value else 0)
        else:
            vidx = pool.add(value)
            raw_ref, dtype, data = vidx, _TYPE_STRING, vidx
        body += struct.pack("<IIIHBBI", _NO_ENTRY, key_idx, raw_ref, 8, 0, dtype, data)
    attr_ext = struct.pack("<IIHHHHHH", _NO_ENTRY, name_idx, 20, 20, len(attrs), 0, 0, 0)
    payload = attr_ext + bytes(body)
    size = 16 + len(payload)
    node = struct.pack("<HHII", 0x0102, 16, size, 0xFFFFFFFF) + struct.pack("<I", _NO_ENTRY)
    return node + payload


def _end_element(pool: _Pool, tag: str) -> bytes:
    name_idx = pool.add(tag)
    node = struct.pack("<HHII", 0x0103, 16, 24, 0xFFFFFFFF) + struct.pack("<I", _NO_ENTRY)
    return node + struct.pack("<II", _NO_ENTRY, name_idx)


# A node is (tag, attrs, children).
Node = tuple[str, dict[str, AttrValue], "list[Node]"]


def build_axml(tree: Node) -> bytes:
    """Encode a (tag, attrs, children) tree into a full binary AXML file."""
    pool = _Pool()
    nodes = bytearray()

    def walk(node: Node) -> None:
        tag, attrs, children = node
        nodes.extend(_start_element(pool, tag, attrs))
        for child in children:
            walk(child)
        nodes.extend(_end_element(pool, tag))

    walk(tree)
    body = pool.encode() + bytes(nodes)
    total = 8 + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + body
