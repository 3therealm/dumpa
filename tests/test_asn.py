"""ASN/country lookup: fail-soft fetch, cache round-trip, and offline enrichment."""

from __future__ import annotations

import datetime
import json
from pathlib import Path

from dumpa.core import asn
from dumpa.core.report import Confidence, Finding, FindingState
from dumpa.core.workspace import Workspace


def test_is_valid_host_rejects_urls_and_junk() -> None:
    assert asn.is_valid_host("api.example.com")
    assert not asn.is_valid_host("https://api.example.com/path")
    assert not asn.is_valid_host("")
    assert not asn.is_valid_host("has space.com")


def test_fetch_no_network_is_none(tmp_path: Path) -> None:
    out = asn.fetch_asn_geo("example.com", cache_dir=tmp_path, allow_network=False, timeout=1)
    assert out is None


def test_cache_round_trip(tmp_path: Path) -> None:
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    info = asn.AsnGeoInfo(host="example.com", asn="AS15169 Google LLC",
                          org="Google LLC", country="US", fetched=now.isoformat())
    asn._write_cache(tmp_path, info)
    got = asn.fetch_asn_geo("example.com", cache_dir=tmp_path, allow_network=False,
                            timeout=1, now=now)
    assert got == info


def test_cache_expired_then_no_network(tmp_path: Path) -> None:
    stale = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    info = asn.AsnGeoInfo(host="example.com", asn="AS1", org="x", country="US",
                          fetched=stale.isoformat())
    asn._write_cache(tmp_path, info)
    later = stale + datetime.timedelta(days=999)
    assert asn.fetch_asn_geo("example.com", cache_dir=tmp_path, allow_network=False,
                             timeout=1, ttl_days=90, now=later) is None


def test_parse_failed_status_is_none() -> None:
    assert asn._parse(json.dumps({"status": "fail"}), "x.com", "t") is None
    assert asn._parse("not json", "x.com", "t") is None


def test_parse_success() -> None:
    raw = json.dumps({"status": "success", "as": "AS15169 Google LLC",
                      "org": "Google LLC", "countryCode": "US"})
    info = asn._parse(raw, "x.com", "t")
    assert info is not None
    assert info.asn == "AS15169 Google LLC" and info.country == "US"


def test_enrich_offline_uses_cache(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    now = datetime.datetime.now(datetime.UTC)        # within TTL of the real lookup clock
    asn._write_cache(ws.asn_cache_dir, asn.AsnGeoInfo(
        host="api.example.com", asn="AS13335 Cloudflare", org="Cloudflare",
        country="US", fetched=now.isoformat()))
    findings = [Finding(kind="endpoint", subject="api.example.com",
                        confidence=Confidence.LOW, state=FindingState.PRESENT)]
    out = asn.enrich_asn_geo(findings, ws, allow_network=False, timeout=1)
    f = out[0]
    assert f.attributes["country"] == "US"
    assert f.attributes["asn"] == "AS13335 Cloudflare"
    assert any(e.tool == asn.const_asn_tool for e in f.evidence)


def test_enrich_offline_no_cache_is_noop(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    findings = [Finding(kind="endpoint", subject="api.example.com",
                        confidence=Confidence.LOW)]
    out = asn.enrich_asn_geo(findings, ws, allow_network=False, timeout=1)
    assert out == findings          # unchanged -> default report is reproducible
