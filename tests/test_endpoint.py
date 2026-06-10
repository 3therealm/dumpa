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


def test_paths_attribute_split_out(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "a.txt").write_bytes(
        b"https://api.example.com/v1/track https://api.example.com/v2/log?x=1")
    f = next(x for x in endpoint.scan(ws) if x.subject == "api.example.com")
    paths = f.attributes["paths"].split("; ")
    assert "/v1/track" in paths
    assert "/v2/log?x=1" in paths


def test_harvest_urls_dedupes_pairs() -> None:
    pairs = endpoint.harvest_urls(b"see https://a.com/x and https://a.com/x and https://b.io/")
    assert (sorted(pairs)) == [("a.com", "https://a.com/x"), ("b.io", "https://b.io/")]


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


def _ips(findings: list) -> dict:
    return {f.subject: f for f in findings if f.kind == "ip-endpoint"}


def test_extracts_public_ip_with_port(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "a.txt").write_bytes(b'connect 8.8.8.8:53 now')
    ips = _ips(endpoint.scan(ws))
    assert "8.8.8.8" in ips
    assert ips["8.8.8.8"].attributes["scope"] == "public"
    assert ips["8.8.8.8"].locations[0].domain is None     # kept out of domain exports


def test_multicast_ip_without_port(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "a.txt").write_bytes(b'ssdp 239.255.255.250 group')
    ips = _ips(endpoint.scan(ws))
    assert ips["239.255.255.250"].attributes["scope"] == "multicast"


def test_portless_unicast_is_not_harvested(tmp_path: Path) -> None:
    # indistinguishable from a version string without context -> intentionally skipped
    ws = _ws(tmp_path)
    (ws.extracted_dir / "a.txt").write_bytes(b'sdk 3.0.1.1 and host 8.8.8.8 alone')
    assert _ips(endpoint.scan(ws)) == {}


def test_private_ip_with_port_tagged(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "a.txt").write_bytes(b'lan 192.168.1.1:8080 cgnat 100.64.0.1:9000')
    ips = _ips(endpoint.scan(ws))
    assert ips["192.168.1.1"].attributes["scope"] == "private"
    assert ips["100.64.0.1"].attributes["scope"] == "private"


def test_version_string_not_an_ip(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "a.txt").write_bytes(b'version 1.2.3.4.5:80 build')
    assert _ips(endpoint.scan(ws)) == {}


def test_reserved_and_loopback_dropped(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "a.txt").write_bytes(
        b'0.0.0.0:80 127.0.0.1:8080 255.255.255.255:1 250.1.2.3:9')
    assert _ips(endpoint.scan(ws)) == {}


def test_url_host_ip_not_double_counted_as_bare(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "a.txt").write_bytes(b'http://203.0.113.7:8080/path')
    findings = endpoint.scan(ws)
    # captured once as a URL host, not again as a bare ip-endpoint
    assert "203.0.113.7" in {f.subject for f in findings if f.kind == "endpoint"}
    assert _ips(findings) == {}
