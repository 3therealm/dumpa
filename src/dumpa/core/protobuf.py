"""Schema-free protobuf wire-format string walker (zero-dep).

A serialized protobuf is a flat stream of `(tag, value)` records: `tag = (field<<3)|wire_type`
encoded as a varint, then a value sized by the wire type. Without the `.proto` schema we
cannot name fields or know their types, but we can walk the wire format and pull printable
strings out of length-delimited (wire-type-2) fields — which is where URLs, hostnames, and
keys live.

A wire-type-2 payload is ambiguous: string, raw bytes, nested message, or a packed repeated
field. The heuristic here is *text-first*: a payload that decodes as a printable string is
surfaced as a leaf string; otherwise (binary) it is re-walked as a nested message, depth-
guarded. Any malformed varint or a length that overruns the buffer ends the walk for that
message — a hostile or truncated blob yields whatever parsed cleanly before the fault, never
an exception. Wire types 3/4 (deprecated groups) and any unknown type stop the current
message (there is no length to skip them safely).

Distinct from `core.dex._uleb128` (which is DEX-specific, raises, and is 5-byte-bounded):
`read_varint` is a generic, fail-soft 64-bit reader.
"""

from __future__ import annotations

from collections.abc import Iterator

_WIRE_VARINT = 0
_WIRE_I64 = 1
_WIRE_LEN = 2
_WIRE_I32 = 5

_DEFAULT_MAX_DEPTH = 2
_DEFAULT_MIN_LEN = 4


def read_varint(buf: bytes, pos: int) -> tuple[int, int] | None:
    """Read a base-128 varint at `pos`; return (value, next_pos) or None on truncation/overlong."""
    result = 0
    shift = 0
    while pos < len(buf):
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift >= 64:                 # overlong: not a valid 64-bit varint
            return None
    return None                         # ran off the end with the continuation bit set


def _as_text(payload: bytes, min_len: int) -> str | None:
    """Return `payload` as a printable string, or None if it is short / not printable text."""
    if len(payload) < min_len:
        return None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() else None


def _walk(buf: bytes, base: int, depth: int, max_depth: int, min_len: int,
          out: list[tuple[int, int, str]]) -> None:
    pos = 0
    n = len(buf)
    while pos < n:
        tag = read_varint(buf, pos)
        if tag is None:
            return
        key, pos = tag
        field = key >> 3
        wire = key & 0x07
        if wire == _WIRE_VARINT:
            v = read_varint(buf, pos)
            if v is None:
                return
            pos = v[1]
        elif wire == _WIRE_I64:
            pos += 8
            if pos > n:
                return
        elif wire == _WIRE_I32:
            pos += 4
            if pos > n:
                return
        elif wire == _WIRE_LEN:
            ln = read_varint(buf, pos)
            if ln is None:
                return
            length, pos = ln
            if pos + length > n:
                return
            payload = buf[pos:pos + length]
            payload_off = base + pos
            pos += length
            text = _as_text(payload, min_len)
            if text is not None:
                out.append((field, payload_off, text))
            elif depth < max_depth:
                _walk(payload, payload_off, depth + 1, max_depth, min_len, out)
        else:
            return                      # groups (3/4) or unknown: no safe length to skip


def walk_strings(buf: bytes, *, max_depth: int = _DEFAULT_MAX_DEPTH,
                 min_len: int = _DEFAULT_MIN_LEN) -> list[tuple[int, int, str]]:
    """Walk a protobuf blob, returning (field_number, absolute_offset, text) per string field.

    `offset` is the absolute byte offset of the field's payload within `buf`, so a finding can
    point a caller back at the exact location even for strings recovered from nested messages.
    """
    out: list[tuple[int, int, str]] = []
    _walk(buf, 0, 0, max_depth, min_len, out)
    return out


def iter_strings(buf: bytes, **kw: int) -> Iterator[tuple[int, int, str]]:
    """Iterator view over `walk_strings` for callers that only stream the results."""
    yield from walk_strings(buf, **kw)
