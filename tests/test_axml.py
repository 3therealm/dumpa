"""Binary AXML decoder — validated against a hand-built encoder (no real apk needed)."""

from __future__ import annotations

import struct

import pytest

from dumpa.core.axml import AttrValue, parse_axml
from dumpa.core.errors import AxmlError

_NO_ENTRY = 0xFFFFFFFF
_TYPE_STRING = 0x03
_TYPE_INT_BOOLEAN = 0x12


class _Pool:
    """Builds a UTF-8 string pool and hands out indices."""

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


def _build(tree: tuple) -> bytes:
    """tree = (tag, attrs, [children]); emit a full AXML file."""
    pool = _Pool()
    nodes = bytearray()

    def walk(node: tuple) -> None:
        tag, attrs, children = node
        nodes.extend(_start_element(pool, tag, attrs))
        for child in children:
            walk(child)
        nodes.extend(_end_element(pool, tag))

    walk(tree)
    pool_blob = pool.encode()
    body = pool_blob + bytes(nodes)
    total = 8 + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + body


def test_decodes_package_and_string_attr() -> None:
    data = _build(("manifest", {"package": "com.example.game"}, []))
    doc = parse_axml(data)
    assert doc.root is not None
    assert doc.root.tag == "manifest"
    assert doc.root.attrs["package"] == "com.example.game"


def test_decodes_boolean_attrs() -> None:
    tree = ("manifest", {"package": "p"}, [
        ("application", {"debuggable": True, "allowBackup": False}, []),
    ])
    doc = parse_axml(_build(tree))
    assert doc.root is not None
    app = doc.root.children[0]
    assert app.tag == "application"
    assert app.attrs["debuggable"] is True
    assert app.attrs["allowBackup"] is False


def test_nested_tree_and_iter() -> None:
    tree = ("manifest", {}, [
        ("uses-permission", {"name": "android.permission.INTERNET"}, []),
        ("application", {}, [
            ("activity", {"name": ".Main", "exported": True}, [
                ("intent-filter", {}, [
                    ("action", {"name": "android.intent.action.MAIN"}, []),
                ]),
            ]),
        ]),
    ])
    doc = parse_axml(_build(tree))
    assert doc.root is not None
    tags = [e.tag for e in doc.root.iter()]
    assert tags == ["manifest", "uses-permission", "application", "activity",
                    "intent-filter", "action"]
    activity = next(e for e in doc.root.iter() if e.tag == "activity")
    assert activity.attrs["exported"] is True


def test_rejects_non_axml() -> None:
    with pytest.raises(AxmlError, match="not an AXML"):
        parse_axml(b"\x00\x00\x08\x00" + b"\x00" * 16)


def test_rejects_tiny_input() -> None:
    with pytest.raises(AxmlError, match="too small"):
        parse_axml(b"\x03\x00")


def test_rejects_bad_chunk_size() -> None:
    # Valid file header, but the first inner chunk claims an impossible size.
    bad = struct.pack("<HHI", 0x0003, 8, 16) + struct.pack("<HHI", 0x0001, 8, 9999)
    with pytest.raises(AxmlError, match="bad chunk size"):
        parse_axml(bad)
