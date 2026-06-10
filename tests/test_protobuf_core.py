"""core.protobuf: schema-free wire-format varint + string walker."""

from __future__ import annotations

from dumpa.core import protobuf


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _len_field(field_num: int, payload: bytes) -> bytes:
    """Encode a wire-type-2 (length-delimited) field."""
    return _varint((field_num << 3) | 2) + _varint(len(payload)) + payload


def _varint_field(field_num: int, value: int) -> bytes:
    """Encode a wire-type-0 (varint) field."""
    return _varint((field_num << 3) | 0) + _varint(value)


# --- read_varint -------------------------------------------------------------

def test_read_varint_single_byte() -> None:
    assert protobuf.read_varint(b"\x08", 0) == (8, 1)


def test_read_varint_multibyte() -> None:
    assert protobuf.read_varint(b"\xac\x02", 0) == (300, 2)


def test_read_varint_truncated_returns_none() -> None:
    assert protobuf.read_varint(b"\x80", 0) is None      # continuation bit, no next byte


def test_read_varint_overlong_returns_none() -> None:
    assert protobuf.read_varint(b"\x80" * 11, 0) is None  # past 64 bits


# --- walk_strings ------------------------------------------------------------

def test_walk_extracts_string_field() -> None:
    blob = _len_field(1, b"https://api.example.com")
    assert any(t == "https://api.example.com" for _f, _o, t in protobuf.walk_strings(blob))


def test_walk_offset_points_at_payload() -> None:
    blob = _varint_field(3, 7) + _len_field(1, b"hello-world")
    field, off, text = next(h for h in protobuf.walk_strings(blob) if h[2] == "hello-world")
    assert field == 1
    assert blob[off:off + len(text.encode())] == b"hello-world"


def test_walk_recurses_into_nested_message() -> None:
    inner = _len_field(1, b"https://inner.example.com")
    blob = _len_field(2, inner)
    assert any(t == "https://inner.example.com" for _f, _o, t in protobuf.walk_strings(blob))


def test_walk_skips_short_and_non_text() -> None:
    assert protobuf.walk_strings(_len_field(1, b"hi")) == []          # below min_len
    assert protobuf.walk_strings(_len_field(1, b"\xff\xfe\x00\x01")) == []  # not text/message


def test_walk_truncated_length_is_graceful() -> None:
    blob = _varint((1 << 3) | 2) + _varint(100) + b"short"           # claims 100, has 5
    assert protobuf.walk_strings(blob) == []


def test_walk_unknown_wire_type_stops_cleanly() -> None:
    # a valid string field, then a group-start (wire 3) we don't decode -> stop, keep the string
    blob = _len_field(1, b"https://kept.example.com") + _varint((2 << 3) | 3)
    assert any(t == "https://kept.example.com" for _f, _o, t in protobuf.walk_strings(blob))
