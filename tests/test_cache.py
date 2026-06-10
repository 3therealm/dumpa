"""Per-scanner content-hash caching: key derivation, round-trip, and run_all reuse."""

from __future__ import annotations

from pathlib import Path

from dumpa.core import cache
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace, make_meta
from dumpa.scanners import ScannerSpec, _run_spec, run_all

_SHA = "a" * 64


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


def _meta(input_sha256: str = _SHA):
    return make_meta(
        input_path=Path("app.apk"), input_sha256=input_sha256, input_size=10,
        input_type="apk", tool_versions={},
    )


def _sample() -> list[Finding]:
    return [Finding(
        kind="tracker", subject="Firebase Analytics", confidence=Confidence.HIGH,
        state=FindingState.REFERENCED, attributes={"owner": "Google", "category": "analytics"},
        evidence=[Evidence(description="matched", snippet="Lcom/google/firebase", file_sha256="b" * 64)],
        locations=[Location(file_path="classes.dex", file_offset=42)],
    )]


def _touch(root: Path, rel: str, data: bytes = b"\x00") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


# --- key derivation ----------------------------------------------------------

def test_key_is_deterministic() -> None:
    assert cache.compute_scanner_key(_SHA, {"trackers": "1.0"}) == \
        cache.compute_scanner_key(_SHA, {"trackers": "1.0"})


def test_key_independent_of_bundle_dict_order() -> None:
    assert cache.compute_scanner_key(_SHA, {"a": "1", "b": "2"}) == \
        cache.compute_scanner_key(_SHA, {"b": "2", "a": "1"})


def test_key_changes_with_input_hash() -> None:
    assert cache.compute_scanner_key(_SHA, {}) != cache.compute_scanner_key("c" * 64, {})


def test_key_changes_with_bundle_version() -> None:
    assert cache.compute_scanner_key(_SHA, {"trackers": "1.0"}) != \
        cache.compute_scanner_key(_SHA, {"trackers": "2.0"})


def test_tool_versions_none_matches_omitted() -> None:
    assert cache.compute_scanner_key(_SHA, {"a": "1"}, None) == \
        cache.compute_scanner_key(_SHA, {"a": "1"})
    assert cache.compute_scanner_key(_SHA, {"a": "1"}, {}) == \
        cache.compute_scanner_key(_SHA, {"a": "1"})


def test_key_changes_with_tool_version() -> None:
    assert cache.compute_scanner_key(_SHA, {}, {"radare2": "5.9.0"}) != \
        cache.compute_scanner_key(_SHA, {}, {"radare2": "6.0.0"})


def test_key_independent_of_tool_dict_order() -> None:
    assert cache.compute_scanner_key(_SHA, {}, {"x": "1", "y": "2"}) == \
        cache.compute_scanner_key(_SHA, {}, {"y": "2", "x": "1"})


# --- read / write round-trip -------------------------------------------------

def test_round_trip_preserves_findings(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    findings = _sample()
    cache.write_scanner_cache(ws, "tracker", "k1", findings)
    assert cache.read_scanner_cache(ws, "tracker", "k1") == findings


def test_round_trip_empty_findings(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    cache.write_scanner_cache(ws, "native", "k1", [])
    assert cache.read_scanner_cache(ws, "native", "k1") == []


def test_miss_when_file_absent(tmp_path: Path) -> None:
    assert cache.read_scanner_cache(_ws(tmp_path), "tracker", "k1") is None


def test_miss_on_key_mismatch(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    cache.write_scanner_cache(ws, "tracker", "k1", _sample())
    assert cache.read_scanner_cache(ws, "tracker", "k2") is None


def test_miss_on_corrupt_json(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    path = ws.cache_dir / cache.const_dir_cache_scanners / "tracker.json"
    path.parent.mkdir(parents=True)
    path.write_text("{ not json", encoding="UTF-8")
    assert cache.read_scanner_cache(ws, "tracker", "k1") is None


def test_miss_on_schema_drift(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    path = ws.cache_dir / cache.const_dir_cache_scanners / "tracker.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"schema": 999, "key": "k1", "findings": []}', encoding="UTF-8")
    assert cache.read_scanner_cache(ws, "tracker", "k1") is None


# --- _run_spec: hit avoids recompute ----------------------------------------

def test_run_spec_caches_and_skips_recompute(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    meta = _meta()
    calls: list[int] = []

    def fn(_ws: Workspace) -> list[Finding]:
        calls.append(1)
        return _sample()

    spec = ScannerSpec("faketest", fn)
    first = _run_spec(ws, spec, meta)
    second = _run_spec(ws, spec, meta)
    assert calls == [1]            # fn ran once; second call served from cache
    assert second == first == _sample()


def test_run_spec_recomputes_when_meta_input_changes(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    calls: list[int] = []

    def fn(_ws: Workspace) -> list[Finding]:
        calls.append(1)
        return _sample()

    spec = ScannerSpec("faketest", fn)
    _run_spec(ws, spec, _meta(_SHA))
    _run_spec(ws, spec, _meta("d" * 64))   # different input -> different key -> recompute
    assert calls == [1, 1]


def test_run_spec_no_cache_without_meta(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    calls: list[int] = []

    def fn(_ws: Workspace) -> list[Finding]:
        calls.append(1)
        return _sample()

    spec = ScannerSpec("faketest", fn)
    _run_spec(ws, spec, None)
    _run_spec(ws, spec, None)
    assert calls == [1, 1]                  # no meta -> no key -> never cached
    assert not ws.cache_dir.exists()


def test_run_spec_cacheable_false_skips_cache_with_meta(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    meta = _meta()
    calls: list[int] = []

    def fn(_ws: Workspace) -> list[Finding]:
        calls.append(1)
        return _sample()

    spec = ScannerSpec("faketest", fn, cacheable=False)
    _run_spec(ws, spec, meta)
    _run_spec(ws, spec, meta)
    assert calls == [1, 1]
    assert not ws.cache_dir.exists()


# --- run_all: identical output cached vs cold; cache files written -----------

def test_run_all_caches_and_reproduces(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")
    ws.write_meta(_meta())

    cold = run_all(ws)
    assert (ws.cache_dir / cache.const_dir_cache_scanners / "engine.json").is_file()
    assert (ws.cache_dir / cache.const_dir_cache_scanners / "unity.json").is_file()

    warm = run_all(ws)
    assert warm == cold                     # hit reproduces a cold run byte-for-byte


def test_run_all_no_cache_writes_nothing(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")
    ws.write_meta(_meta())
    run_all(ws, use_cache=False)
    assert not ws.cache_dir.exists()
