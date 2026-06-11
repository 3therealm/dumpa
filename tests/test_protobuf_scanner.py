"""scanners.protobuf: decode .pb blobs, mine endpoints + secrets from string fields."""

from __future__ import annotations

from pathlib import Path

from dumpa.core.workspace import Workspace
from dumpa.scanners import protobuf


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
    return _varint((field_num << 3) | 2) + _varint(len(payload)) + payload


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


def test_extracts_url_from_protobuf_string_field(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "config.pb").write_bytes(
        _len_field(1, b"https://api.example.com/v1/track"))
    findings = protobuf.scan(ws)
    f = next((x for x in findings if x.subject == "api.example.com"), None)
    assert f is not None
    assert f.kind == "endpoint"
    assert f.locations[0].file_path == "config.pb"
    assert f.locations[0].domain == "api.example.com"
    assert any("https://api.example.com" in (e.snippet or "") for e in f.evidence)


def test_extracts_secret_from_protobuf_string_field(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    key = b"AIza" + b"0" * 35                     # matches the Google API key rule
    (ws.extracted_dir / "cfg.pb").write_bytes(_len_field(5, key))
    findings = protobuf.scan(ws)
    f = next((x for x in findings if x.kind == "secret"), None)
    assert f is not None
    assert f.subject == "Google API key"
    assert f.locations[0].file_path == "cfg.pb"


def test_url_in_nested_message_is_found(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    inner = _len_field(1, b"https://nested.example.com")
    (ws.extracted_dir / "n.pb").write_bytes(_len_field(2, inner))
    findings = protobuf.scan(ws)
    assert any(x.subject == "nested.example.com" for x in findings)


def test_non_pb_files_are_ignored(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    # same payload, but a .bin extension is outside the protobuf target globs
    (ws.extracted_dir / "data.bin").write_bytes(_len_field(1, b"https://x.example.com"))
    assert protobuf.scan(ws) == []


def test_no_extracted_dir_returns_empty(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    assert protobuf.scan(ws) == []
