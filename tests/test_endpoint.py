"""Endpoint (URL/host) extraction scanner."""

from __future__ import annotations

from pathlib import Path

from dumpa.core.workspace import Workspace
from dumpa.scanners import endpoint


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


def test_extracts_host_and_url(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "config.json").write_bytes(
        b'{"url":"https://api.example.com/v1/track?x=1"}')
    findings = endpoint.scan(ws)
    f = next((x for x in findings if x.subject == "api.example.com"), None)
    assert f is not None
    assert f.kind == "endpoint"
    assert f.locations[0].domain == "api.example.com"
    assert any(e.snippet == "https://api.example.com/v1/track?x=1" for e in f.evidence)


def test_dedupes_by_host(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "a.txt").write_bytes(b"https://x.com/a and https://x.com/b and https://y.com/")
    hosts = sorted(f.subject for f in endpoint.scan(ws))
    assert hosts == ["x.com", "y.com"]


def test_url_spanning_chunk_boundary(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    url = b"https://boundary.example.org/path/seg"
    pad = b"\x00" * ((1 << 20) - 12)   # URL starts just before the 1 MiB chunk edge
    (ws.extracted_dir / "classes.dex").write_bytes(pad + url + b"\x00" * 8)
    hosts = {f.subject for f in endpoint.scan(ws)}
    assert "boundary.example.org" in hosts


def test_no_urls(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "a.txt").write_bytes(b"nothing here but text")
    assert endpoint.scan(ws) == []
