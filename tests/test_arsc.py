"""Tests for the zero-dep resources.arsc parser (core.arsc)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dumpa.core.arsc import parse_arsc
from dumpa.core.errors import ArscError
from dumpa.core.report import Confidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace
from dumpa.scanners import enrich_resource_names, resources
from _arsc_build import build_arsc


def test_parses_package_and_string_entries() -> None:
    data = build_arsc("com.example", "string", [
        ("api_url", "https://api.example.com/v1"),
        ("app_name", "Demo"),
    ])
    table = parse_arsc(data)
    assert len(table.packages) == 1
    pkg = table.packages[0]
    assert pkg.id == 0x7F
    assert pkg.name == "com.example"
    by_name = {e.name: e.value for e in pkg.entries}
    assert by_name == {"api_url": "https://api.example.com/v1", "app_name": "Demo"}
    assert pkg.type_counts() == {"string": 2}


def test_iter_strings_yields_values() -> None:
    data = build_arsc("com.example", "string", [("api_url", "https://api.example.com/v1")])
    rows = list(parse_arsc(data).iter_strings())
    assert ("com.example", "string", "api_url", "https://api.example.com/v1") == rows[0][:4]


def test_locate_maps_value_offset_to_resource() -> None:
    url = "https://api.example.com/v1"
    data = build_arsc("com.example", "string", [("api_url", url), ("app_name", "Demo")])
    table = parse_arsc(data)
    # the value's bytes live at this offset; a content scanner would record one inside it
    offset = next(o for _p, _t, n, _v, o in table.iter_strings() if n == "api_url")
    assert table.locate(offset) == ("api_url", url)
    assert table.locate(offset + 5) == ("api_url", url)      # mid-string still attributes
    assert table.locate(0) is None                            # in the header, owns nothing


def test_not_a_table_raises() -> None:
    with pytest.raises(ArscError, match="not a resource table"):
        parse_arsc(b"\x03\x00\x08\x00" + b"\x00" * 16)        # AXML magic, not ARSC


def test_too_small_raises() -> None:
    with pytest.raises(ArscError, match="too small"):
        parse_arsc(b"\x02\x00")


def _ws_with_arsc(tmp_path: Path, entries: list[tuple[str, str]]) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    (ws.extracted_dir / "resources.arsc").write_bytes(
        build_arsc("com.example", "string", entries))
    return ws


def test_scanner_emits_finding_and_sidecar(tmp_path: Path) -> None:
    ws = _ws_with_arsc(tmp_path, [("api_url", "https://api.example.com/v1"),
                                  ("app_name", "Demo")])
    findings = resources.scan(ws)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "resource-table"
    assert f.subject == "com.example"
    assert f.attributes["string_count"] == "2"
    sidecar = ws.resources_dir / "com.example.json"
    payload = json.loads(sidecar.read_text())
    assert payload["type_counts"] == {"string": 2}


def test_enrich_attributes_arsc_offset_to_resource(tmp_path: Path) -> None:
    url = "https://api.example.com/v1"
    ws = _ws_with_arsc(tmp_path, [("api_url", url)])
    # offset of the value's bytes, as a content scanner inside resources.arsc would record
    offset = next(o for *_h, o in parse_arsc((ws.extracted_dir / "resources.arsc")
                                              .read_bytes()).iter_strings())
    finding = Finding(kind="endpoint", subject="api.example.com",
                      confidence=Confidence.LOW, state=FindingState.PRESENT,
                      locations=[Location(file_path="resources.arsc", file_offset=offset)])
    [enriched] = enrich_resource_names([finding], ws)
    assert any(e.tool == "resource-attribution" and e.snippet == "api_url"
               for e in enriched.evidence)


def test_enrich_noop_without_arsc_offset(tmp_path: Path) -> None:
    ws = _ws_with_arsc(tmp_path, [("api_url", "https://api.example.com/v1")])
    finding = Finding(kind="endpoint", subject="x.com", confidence=Confidence.LOW,
                      locations=[Location(file_path="classes.dex", file_offset=10)])
    assert enrich_resource_names([finding], ws) == [finding]
