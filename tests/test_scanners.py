"""Engine + Unity scanners and primary_engine selection."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from dumpa.core.domains import DomainOwner, DomainTable
from dumpa.core.report import Confidence, Evidence, Finding, Location
from dumpa.core.workspace import Workspace
from dumpa.scanners import engine as engine_scanner
from dumpa.scanners import (
    enrich_domain_attribution,
    primary_engine,
    run_all,
    run_selected,
)
from dumpa.scanners import tracker as tracker_scanner
from dumpa.scanners import unity as unity_scanner

_META_MAGIC = 0xFAB11BAF


def _touch(root: Path, rel: str, data: bytes = b"\x00") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _metadata_blob(version: int) -> bytes:
    return struct.pack("<Ii", _META_MAGIC, version) + b"\x00" * 16


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


# --- engine scanner ----------------------------------------------------------

def test_engine_scan_detects_unity(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")
    findings = engine_scanner.scan(ws)
    assert any(f.kind == "engine" and f.subject == "Unity" for f in findings)


# --- tracker scanner ---------------------------------------------------------

def test_tracker_scan_detects_firebase(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "classes.dex", b"junk Lcom/google/firebase/analytics; junk")
    findings = tracker_scanner.scan(ws)
    fb = next((f for f in findings if f.subject == "Firebase Analytics"), None)
    assert fb is not None
    assert fb.kind == "tracker"
    assert fb.attributes["owner"] == "Google"
    assert fb.attributes["category"] == "analytics"


def test_tracker_scan_clean_apk(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "classes.dex", b"no trackers in this dex")
    assert tracker_scanner.scan(ws) == []


def test_engine_scan_no_extracted_dir(tmp_path: Path) -> None:
    assert engine_scanner.scan(Workspace(root=tmp_path / "missing")) == []


# --- unity scanner -----------------------------------------------------------

def test_unity_il2cpp_backend_and_metadata(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")
    _touch(ws.extracted_dir, "assets/bin/Data/Managed/Metadata/global-metadata.dat",
           _metadata_blob(29))
    subjects = {f.subject for f in unity_scanner.scan(ws)}
    assert "Unity scripting backend: IL2CPP" in subjects
    assert "IL2CPP metadata version 29" in subjects


def test_unity_mono_backend(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libmonobdwgc-2.0.so")
    subjects = {f.subject for f in unity_scanner.scan(ws)}
    assert "Unity scripting backend: Mono" in subjects


def test_unity_bad_metadata_magic(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")
    _touch(ws.extracted_dir, "assets/bin/Data/Managed/Metadata/global-metadata.dat",
           b"NOTMAGIC" + b"\x00" * 8)
    subjects = {f.subject for f in unity_scanner.scan(ws)}
    assert "global-metadata.dat: unrecognized header" in subjects


def test_unity_noop_on_non_unity(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libflutter.so")
    assert unity_scanner.scan(ws) == []


# --- aggregation + primary engine -------------------------------------------

def test_run_all_aggregates(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")
    kinds = {f.kind for f in run_all(ws)}
    assert "engine" in kinds
    assert "engine-detail" in kinds


def test_run_all_does_not_emit_orphan_unity_details(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "res/raw/global-metadata.dat", _metadata_blob(29))
    findings = run_all(ws)
    assert findings == []
    assert primary_engine(findings) is None


def test_primary_engine_prefers_high_confidence() -> None:
    findings = [
        Finding(kind="engine", subject="Defold", confidence=Confidence.MEDIUM),
        Finding(kind="engine", subject="Unity", confidence=Confidence.HIGH),
    ]
    assert primary_engine(findings) == "Unity"


def test_primary_engine_none_when_no_engine() -> None:
    assert primary_engine([Finding(kind="tracker", subject="x", confidence=Confidence.LOW)]) is None


# --- enrich_domain_attribution (C3) -----------------------------------------

def _owner(owner: str, subject: str | None, *, category: str = "ads") -> DomainOwner:
    return DomainOwner(owner=owner, category=category, subject=subject,
                       source="test", version="1")


def _patch_table(monkeypatch: pytest.MonkeyPatch, table: DomainTable) -> None:
    monkeypatch.setattr("dumpa.scanners.build_domain_table", lambda: table)


# real seed: app-measurement.com -> Google / Firebase Analytics / analytics

def test_endpoint_gains_owner_and_category(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    endpoint = Finding(kind="endpoint", subject="app-measurement.com", confidence=Confidence.LOW)
    out = enrich_domain_attribution([endpoint], ws)
    ep = next(f for f in out if f.kind == "endpoint")
    assert ep.attributes["owner"] == "Google"
    assert ep.attributes["category"] == "analytics"
    assert any(ev.tool == "domain-attribution" for ev in ep.evidence)


def test_tracker_gains_domain_location_by_subject(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    tracker = Finding(kind="tracker", subject="Firebase Analytics", confidence=Confidence.HIGH,
                      attributes={"owner": "Google", "category": "analytics"})
    endpoint = Finding(kind="endpoint", subject="app-measurement.com", confidence=Confidence.LOW)
    out = enrich_domain_attribution([tracker, endpoint], ws)
    tr = next(f for f in out if f.kind == "tracker")
    assert any(loc.domain == "app-measurement.com" for loc in tr.locations)
    assert any(ev.tool == "domain-attribution" for ev in tr.evidence)


def test_owner_only_fallback_applies_for_single_tracker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_table(monkeypatch, DomainTable({"acme.com": _owner("Acme", "No Such Subject")}))
    ws = _ws(tmp_path)
    tracker = Finding(kind="tracker", subject="Acme SDK", confidence=Confidence.HIGH,
                      attributes={"owner": "Acme"})
    endpoint = Finding(kind="endpoint", subject="acme.com", confidence=Confidence.LOW)
    out = enrich_domain_attribution([tracker, endpoint], ws)
    tr = next(f for f in out if f.kind == "tracker")
    assert any(loc.domain == "acme.com" for loc in tr.locations)


def test_owner_only_fallback_skipped_for_multiple_trackers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_table(monkeypatch, DomainTable({"acme.com": _owner("Acme", "No Such Subject")}))
    ws = _ws(tmp_path)
    t1 = Finding(kind="tracker", subject="Acme SDK A", confidence=Confidence.HIGH,
                 attributes={"owner": "Acme"})
    t2 = Finding(kind="tracker", subject="Acme SDK B", confidence=Confidence.HIGH,
                 attributes={"owner": "Acme"})
    endpoint = Finding(kind="endpoint", subject="acme.com", confidence=Confidence.LOW)
    out = enrich_domain_attribution([t1, t2, endpoint], ws)
    for tr in (f for f in out if f.kind == "tracker"):
        assert not any(loc.domain == "acme.com" for loc in tr.locations)


def test_subject_match_preferred_over_owner_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Owner has TWO trackers; the table's DomainOwner.subject matches exactly one.
    _patch_table(monkeypatch, DomainTable({"acme.com": _owner("Acme", "Acme SDK B")}))
    ws = _ws(tmp_path)
    t1 = Finding(kind="tracker", subject="Acme SDK A", confidence=Confidence.HIGH,
                 attributes={"owner": "Acme"})
    t2 = Finding(kind="tracker", subject="Acme SDK B", confidence=Confidence.HIGH,
                 attributes={"owner": "Acme"})
    endpoint = Finding(kind="endpoint", subject="acme.com", confidence=Confidence.LOW)
    out = enrich_domain_attribution([t1, t2, endpoint], ws)
    sdk_a = next(f for f in out if f.subject == "Acme SDK A")
    sdk_b = next(f for f in out if f.subject == "Acme SDK B")
    assert any(loc.domain == "acme.com" for loc in sdk_b.locations)
    assert not any(loc.domain == "acme.com" for loc in sdk_a.locations)


def test_existing_owner_attribute_preserved(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    endpoint = Finding(kind="endpoint", subject="app-measurement.com", confidence=Confidence.LOW,
                       attributes={"owner": "Custom"})
    out = enrich_domain_attribution([endpoint], ws)
    ep = next(f for f in out if f.kind == "endpoint")
    assert ep.attributes["owner"] == "Custom"  # present key not overwritten
    assert ep.attributes["category"] == "analytics"  # absent key still added


def test_shared_infra_host_not_attributed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only declaration is a shared-infra host; a subdomain must resolve to None.
    _patch_table(monkeypatch, DomainTable({"firebaseio.com": _owner("X", None, category="infra")}))
    ws = _ws(tmp_path)
    endpoint = Finding(kind="endpoint", subject="tenant.firebaseio.com", confidence=Confidence.LOW)
    out = enrich_domain_attribution([endpoint], ws)
    ep = next(f for f in out if f.kind == "endpoint")
    assert "owner" not in ep.attributes
    assert ep.locations == []


def test_confidence_never_changes(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    findings = [
        Finding(kind="tracker", subject="Firebase Analytics", confidence=Confidence.HIGH,
                attributes={"owner": "Google", "category": "analytics"}),
        Finding(kind="endpoint", subject="app-measurement.com", confidence=Confidence.LOW),
    ]
    before = [f.confidence for f in findings]
    out = enrich_domain_attribution(findings, ws)
    assert [f.confidence for f in out] == before


def test_empty_table_passthrough(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_table(monkeypatch, DomainTable({}))
    ws = _ws(tmp_path)
    findings = [Finding(kind="endpoint", subject="app-measurement.com", confidence=Confidence.LOW)]
    out = enrich_domain_attribution(findings, ws)
    assert out == findings


def test_idempotent(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    findings = [
        Finding(kind="tracker", subject="Firebase Analytics", confidence=Confidence.HIGH,
                attributes={"owner": "Google", "category": "analytics"}),
        Finding(kind="endpoint", subject="app-measurement.com", confidence=Confidence.LOW),
    ]
    once = enrich_domain_attribution(findings, ws)
    twice = enrich_domain_attribution(once, ws)
    tr_once = next(f for f in once if f.kind == "tracker")
    tr_twice = next(f for f in twice if f.kind == "tracker")
    assert [loc.domain for loc in tr_once.locations] == [loc.domain for loc in tr_twice.locations]
    assert len(tr_twice.evidence) == len(tr_once.evidence)
    ep_twice = next(f for f in twice if f.kind == "endpoint")
    ep_once = next(f for f in once if f.kind == "endpoint")
    assert ep_twice.attributes == ep_once.attributes
    assert len(ep_twice.evidence) == len(ep_once.evidence)


def test_host_in_subject_and_location_deduped(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    tracker = Finding(kind="tracker", subject="Firebase Analytics", confidence=Confidence.HIGH,
                      attributes={"owner": "Google", "category": "analytics"})
    # Endpoint carries the host in BOTH subject and a Location.domain.
    endpoint = Finding(
        kind="endpoint", subject="app-measurement.com", confidence=Confidence.LOW,
        evidence=[Evidence(description="host", tool="endpoint")],
        locations=[Location(file_path="x.dex", file_offset=0, domain="app-measurement.com")],
    )
    out = enrich_domain_attribution([tracker, endpoint], ws)
    tr = next(f for f in out if f.kind == "tracker")
    domain_locs = [loc for loc in tr.locations if loc.domain == "app-measurement.com"]
    assert len(domain_locs) == 1


# --- opt-in native_r2 scanner ------------------------------------------------

def test_native_r2_not_in_default_run_all(tmp_path: Path) -> None:
    from dumpa.core.workspace import make_meta
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libfoo.so")
    ws.write_meta(make_meta(input_path=Path("a.apk"), input_sha256="a" * 64,
                            input_size=1, input_type="apk", tool_versions={}))
    findings = run_all(ws)
    assert not [f for f in findings if f.kind == "native-region"]
    assert not [f for f in findings if f.kind == "native-function-summary"]


def test_native_r2_runs_when_requested(tmp_path: Path, monkeypatch) -> None:
    from dumpa.core.r2 import R2Analysis, R2Function, R2Section
    from dumpa.core.workspace import make_meta
    from dumpa.scanners import native_r2

    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libfoo.so")
    ws.write_meta(make_meta(input_path=Path("a.apk"), input_sha256="a" * 64,
                            input_size=1, input_type="apk", tool_versions={}))

    class _Tool:
        version = "radare2 5.9.0"
        argv_prefix = ("radare2",)

    class _Reg:
        def resolve(self, name: str) -> _Tool:
            return _Tool()

    monkeypatch.setattr(native_r2, "build_default_registry", lambda _p: _Reg())
    monkeypatch.setattr(native_r2, "load_config",
                        lambda: type("C", (), {"tool_paths": {}})())
    monkeypatch.setattr(native_r2.r2, "analyze", lambda _p, argv_prefix=("radare2",), version=None: R2Analysis(
        version="radare2 5.9.0", functions=[R2Function("f", 0x10, 8, 1)],
        sections=[R2Section(".text", 0x1000, 0x400, 2048, "-r-x", 7.95)]))

    findings = run_all(ws, extra=("native_r2",), registry=_Reg())
    assert [f for f in findings if f.kind == "native-region"]
    assert [f for f in findings if f.kind == "native-function-summary"]


def test_native_r2_requested_scanner_is_not_cached(tmp_path: Path, monkeypatch) -> None:
    from dumpa.core.r2 import R2Analysis, R2Function, R2Section
    from dumpa.core.workspace import make_meta
    from dumpa.scanners import native_r2

    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libfoo.so")
    ws.write_meta(make_meta(input_path=Path("a.apk"), input_sha256="a" * 64,
                            input_size=1, input_type="apk", tool_versions={}))

    class _Tool:
        version = "radare2 5.9.0"
        argv_prefix = ("radare2",)

    class _Reg:
        def resolve(self, name: str) -> _Tool:
            return _Tool()

    calls: list[int] = []

    def fake(_p, argv_prefix=("radare2",), version=None) -> R2Analysis:
        calls.append(1)
        return R2Analysis(
            version="radare2 5.9.0",
            functions=[R2Function("f", 0x10, 8, 1)],
            sections=[R2Section(".text", 0x1000, 0x400, 2048, "-r-x", 7.95)],
        )

    monkeypatch.setattr(native_r2, "build_default_registry", lambda _p: _Reg())
    monkeypatch.setattr(native_r2, "load_config",
                        lambda: type("C", (), {"tool_paths": {}})())
    monkeypatch.setattr(native_r2.r2, "analyze", fake)

    run_all(ws, extra=("native_r2",), registry=_Reg())
    run_all(ws, extra=("native_r2",), registry=_Reg())

    assert calls == [1, 1]
    assert not (ws.cache_dir / "scanners" / "native_r2.json").exists()


# --- run_selected (focused scan subset + shared enrichment tail) -------------

def test_run_selected_runs_only_named_scanner(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "classes.dex", b"junk Lcom/google/firebase/analytics; junk")
    _touch(ws.extracted_dir, "lib/arm64-v8a/libjiagu.so", b"\x7fELF packed")
    findings = run_selected(ws, ["tracker"])
    kinds = {f.kind for f in findings}
    assert "tracker" in kinds
    assert "protection" not in kinds                 # libjiagu not scanned
    fb = next(f for f in findings if f.subject == "Firebase Analytics")
    assert fb.attributes["owner"] == "Google"        # enrichment tail applied


def test_run_selected_unknown_name_raises(tmp_path: Path) -> None:
    from dumpa.core.errors import DumpaError
    with pytest.raises(DumpaError):
        run_selected(_ws(tmp_path), ["nope"])
