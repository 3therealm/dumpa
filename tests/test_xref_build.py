"""build_xref / query_xref on a synthetic workspace."""

from __future__ import annotations

import json
from pathlib import Path

from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace
from dumpa.core.xref import EntityType, Layer, build_xref, query_xref


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path)
    ws.native_dir.mkdir(parents=True, exist_ok=True)
    ws.dex_dir.mkdir(parents=True, exist_ok=True)
    return ws


def _native_sidecar(ws: Workspace, *, exports: list[dict]) -> None:
    (ws.native_dir / "arm64-v8a__libfoo.so.json").write_text(json.dumps({
        "abi": "arm64-v8a", "lib": "libfoo.so",
        "exports": exports, "imports": [],
    }), encoding="UTF-8")


def _dex_sidecar(ws: Workspace, *, classes: list[str]) -> None:
    (ws.dex_dir / "classes.dex.json").write_text(json.dumps({
        "dex": "classes.dex", "version": 35,
        "classes": [{"name": c, "superclass": None, "methods": [], "fields": []}
                    for c in classes],
    }), encoding="UTF-8")


def _domain_finding(domain: str, paths: list[str]) -> Finding:
    return Finding(
        kind="endpoint", subject=domain, confidence=Confidence.MEDIUM,
        state=FindingState.PRESENT,
        evidence=[Evidence(description="url")],
        locations=[Location(file_path=p, domain=domain) for p in paths],
    )


def test_domain_spans_three_layers(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    findings = [_domain_finding(
        "api.example.com",
        ["lib/arm64-v8a/libfoo.so", "classes.dex", "res/values/strings.xml"],
    )]
    xref = build_xref(ws, findings, input_sha256="abc", built="2026-06-08T00:00:00Z")
    dom = next(e for e in xref.entities
               if e.type is EntityType.DOMAIN and e.key == "api.example.com")
    assert dom.layers == frozenset({Layer.NATIVE, Layer.SMALI, Layer.RESOURCE})
    assert len(dom.appearances) == 3


def test_jni_symbol_joins_dex_class(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _native_sidecar(ws, exports=[{"name": "Java_com_foo_Bar_init", "rva": 4096}])
    _dex_sidecar(ws, classes=["com.foo.Bar"])
    xref = build_xref(ws, [], input_sha256="abc", built="t")
    cls = next(e for e in xref.entities
               if e.type is EntityType.CLASS and e.key == "com.foo.Bar")
    assert cls.layers == frozenset({Layer.NATIVE, Layer.SMALI})


def test_single_layer_entity_excluded_but_queryable(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _native_sidecar(ws, exports=[{"name": "lonely_export", "rva": 16}])
    xref = build_xref(ws, [], input_sha256="abc", built="t")
    assert not any(e.key == "lonely_export" for e in xref.entities)

    found = query_xref(ws, [], "lonely_export")
    assert found is not None
    assert found.type is EntityType.SYMBOL
    assert found.layers == frozenset({Layer.NATIVE})


def test_query_case_insensitive(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _native_sidecar(ws, exports=[{"name": "MixedSymbol", "rva": 16}])
    assert query_xref(ws, [], "mixedsymbol") is None
    assert query_xref(ws, [], "mixedsymbol", case_insensitive=True) is not None


def test_missing_layers_no_crash(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path)   # no dumps/ at all
    xref = build_xref(ws, [], input_sha256="abc", built="t")
    assert xref.entities == ()
    assert Layer.NATIVE not in xref.provenance.layers_present


def test_layers_present_reflects_sources(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _native_sidecar(ws, exports=[{"name": "x", "rva": 1}])
    _dex_sidecar(ws, classes=["com.A"])
    xref = build_xref(ws, [], input_sha256="abc", built="t")
    assert Layer.NATIVE in xref.provenance.layers_present
    assert Layer.SMALI in xref.provenance.layers_present
    assert "cpp-demangle" in xref.provenance.deferred
