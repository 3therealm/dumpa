"""reporting.build_report + JSON file round-trip on a synthetic workspace."""

from __future__ import annotations

import json
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from dumpa.core.report import (
    AppFacts,
    Confidence,
    Finding,
    Report,
    read_json,
    to_json,
    write_json,
)
from dumpa.core.tools import build_default_registry
from dumpa.core.workspace import Workspace, make_meta
from dumpa.reporting import build_report


def _workspace(root: Path) -> Workspace:
    ws = Workspace(root=root)
    ws.prepare_build()
    with zipfile.ZipFile(ws.app_apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00fake")
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 40)
    (ws.extracted_dir / "AndroidManifest.xml").write_bytes(b"\x00")
    ws.write_meta(make_meta(
        input_path=root / "in.apk", input_sha256="c" * 64, input_size=999,
        input_type="apk", tool_versions={"apktool": "3.0.2"},
    ))
    return ws


def test_build_report_facts_from_marker(tmp_path: Path) -> None:
    ws = _workspace(tmp_path / "ws")
    report = build_report(build_default_registry(), ws)
    assert report.facts.input_sha256 == "c" * 64
    assert report.facts.input_size == 999
    assert report.tool_versions == {"apktool": "3.0.2"}
    assert report.findings == []          # manifest-only tree -> no engine detected
    assert report.facts.engine is None
    # corrupt/unsigned synthetic apk -> unsigned warning, no schemes
    assert "apk is unsigned" in report.warnings
    assert report.facts.signing_schemes == []


def test_build_report_detects_engine(tmp_path: Path) -> None:
    ws = _workspace(tmp_path / "ws")
    (ws.extracted_dir / "lib" / "arm64-v8a").mkdir(parents=True)
    (ws.extracted_dir / "lib" / "arm64-v8a" / "libil2cpp.so").write_bytes(b"\x7fELF")
    report = build_report(build_default_registry(), ws)
    assert report.facts.engine == "Unity"
    assert any(f.kind == "engine" and f.subject == "Unity" for f in report.findings)
    assert any(f.kind == "engine-detail" for f in report.findings)


def test_build_report_uses_workspace_optional_scanners(tmp_path: Path, monkeypatch) -> None:
    ws = _workspace(tmp_path / "ws")
    meta = ws.read_meta()
    assert meta is not None
    ws.write_meta(replace(meta, optional_scanners=("native_r2",)))
    seen: list[tuple[str, ...]] = []

    def fake_run_all(_ws, *, use_cache=True, extra=(), registry=None):
        seen.append(extra)
        return []

    monkeypatch.setattr("dumpa.reporting.run_all", fake_run_all)
    build_report(build_default_registry(), ws)
    assert seen == [("native_r2",)]


def test_build_report_explicit_extra_overrides_workspace_optional_scanners(
    tmp_path: Path, monkeypatch
) -> None:
    ws = _workspace(tmp_path / "ws")
    meta = ws.read_meta()
    assert meta is not None
    ws.write_meta(replace(meta, optional_scanners=("native_r2",)))
    seen: list[tuple[str, ...]] = []

    def fake_run_all(_ws, *, use_cache=True, extra=(), registry=None):
        seen.append(extra)
        return []

    monkeypatch.setattr("dumpa.reporting.run_all", fake_run_all)
    build_report(build_default_registry(), ws, extra=())
    assert seen == [()]


def test_report_json_file_round_trip(tmp_path: Path) -> None:
    ws = _workspace(tmp_path / "ws")
    report = build_report(build_default_registry(), ws)
    path = ws.reports_dir / "report.json"
    write_json(report, path)
    assert path.is_file()
    assert read_json(path) == report


def test_read_json_missing_is_none(tmp_path: Path) -> None:
    assert read_json(tmp_path / "nope.json") is None


# ---- split storage layout -------------------------------------------------------------

def _finding(kind: str, subject: str) -> Finding:
    return Finding(kind=kind, subject=subject, confidence=Confidence.LOW)


def _report(findings: list[Finding]) -> Report:
    return Report(
        dumpa_version="9.9.9", created="2026-01-02T03:04:05+00:00", input_path="/in.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1),
        findings=findings,
    )


def _write(tmp_path: Path, report: Report) -> Path:
    path = tmp_path / "reports" / "report.json"
    write_json(report, path)
    return path


def test_split_layout_written(tmp_path: Path) -> None:
    report = _report([
        _finding("dumpcs", "player-manager"),
        _finding("tracker", "AdMob"),
        _finding("endpoint", "api.example.com"),
        _finding("secret", "aws-key"),
        _finding("tracker", "Firebase"),
    ])
    path = _write(tmp_path, report)
    data = json.loads(path.read_text())

    assert data["findings"] is None
    assert data["storage_schema_version"] == 1
    assert data["findings_layout"] == "split-v1"
    assert isinstance(data["report_id"], str) and data["report_id"]
    cats = {e["category"]: e["count"] for e in data["findings_index"]}
    assert cats == {"patterns": 1, "trackers": 2, "network": 1, "security": 1}
    assert sum(cats.values()) == len(report.findings)

    findings_dir = path.parent / "findings"
    assert {p.name for p in findings_dir.glob("*.json")} == {
        "patterns.json", "trackers.json", "network.json", "security.json"}
    trackers = json.loads((findings_dir / "trackers.json").read_text())
    assert trackers["category"] == "trackers"
    assert trackers["report_id"] == data["report_id"]   # per-write id, shared header<->sidecar
    assert all("_ordinal" in f for f in trackers["findings"])


def test_split_round_trip_preserves_order(tmp_path: Path) -> None:
    # interleave categories so category-order != original order
    report = _report([
        _finding("tracker", "A"), _finding("dumpcs", "B"), _finding("endpoint", "C"),
        _finding("tracker", "D"), _finding("secret", "E"), _finding("native-symbol", "F"),
    ])
    path = _write(tmp_path, report)
    restored = read_json(path)
    assert restored == report                       # strict: exact order + content


def test_export_json_emits_inline_findings_from_split(tmp_path: Path) -> None:
    # on-disk report.json is thin, but `dumpa export json` (to_json) emits a whole document
    report = _report([_finding("tracker", "AdMob"), _finding("secret", "k")])
    path = _write(tmp_path, report)
    exported = json.loads(to_json(read_json(path)))
    assert isinstance(exported["findings"], list)
    assert len(exported["findings"]) == 2
    assert "findings_index" not in exported


def test_unknown_kind_goes_to_other(tmp_path: Path) -> None:
    report = _report([_finding("rewrite", "patched"), _finding("totally-new-kind", "x")])
    path = _write(tmp_path, report)
    cats = {e["category"] for e in json.loads(path.read_text())["findings_index"]}
    assert cats == {"other"}
    assert read_json(path) == report


def test_empty_findings_report(tmp_path: Path) -> None:
    report = _report([])
    path = _write(tmp_path, report)
    data = json.loads(path.read_text())
    assert data["findings_index"] == []
    assert not (path.parent / "findings").exists()
    assert read_json(path) == report


def test_stale_sidecar_cleaned_on_rewrite(tmp_path: Path) -> None:
    path = _write(tmp_path, _report([_finding("secret", "k")]))
    assert (path.parent / "findings" / "security.json").is_file()
    # rewrite with no security findings -> the stale sidecar is gone
    write_json(_report([_finding("tracker", "AdMob")]), path)
    findings_dir = path.parent / "findings"
    assert not (findings_dir / "security.json").exists()
    assert {p.name for p in findings_dir.glob("*.json")} == {"trackers.json"}


def test_back_compat_monolithic_report(tmp_path: Path) -> None:
    # an old-style report.json (inline findings list, no findings_index) still reads
    report = _report([_finding("tracker", "AdMob")])
    data = report.to_dict()                          # inline findings, no index
    path = tmp_path / "reports" / "report.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(data))
    assert read_json(path) == report


def test_old_reader_fails_closed_on_split(tmp_path: Path) -> None:
    # a new split report.json carries findings: null; the *old* decode path
    # (Report.from_dict over the raw dict) raises rather than reading empty.
    path = _write(tmp_path, _report([_finding("tracker", "AdMob")]))
    data = json.loads(path.read_text())
    assert data["findings"] is None
    with pytest.raises(TypeError):
        Report.from_dict(data)


# ---- split storage: strict corruption handling (all -> None) --------------------------

def _split(tmp_path: Path) -> Path:
    return _write(tmp_path, _report([
        _finding("tracker", "AdMob"), _finding("secret", "k"), _finding("dumpcs", "p"),
    ]))


def _patch_index(path: Path, mutate) -> None:
    data = json.loads(path.read_text())
    mutate(data)
    path.write_text(json.dumps(data))


def _patch_sidecar(path: Path, category: str, mutate) -> None:
    sidecar = path.parent / "findings" / f"{category}.json"
    data = json.loads(sidecar.read_text())
    mutate(data)
    sidecar.write_text(json.dumps(data))


def test_corrupt_both_inline_and_index(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d.__setitem__("findings", [_finding("x", "y").to_dict()]))
    assert read_json(path) is None


def test_corrupt_neither_findings_nor_index(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"schema_version": 2, "dumpa_version": "1",
                                "created": "t", "input_path": "/x", "facts": {}}))
    assert read_json(path) is None


def test_corrupt_non_list_index(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d.__setitem__("findings_index", {"not": "a list"}))
    assert read_json(path) is None


def test_corrupt_duplicate_category(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d["findings_index"].append(dict(d["findings_index"][0])))
    assert read_json(path) is None


def test_corrupt_bad_file_value(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d["findings_index"][0].__setitem__("file", "elsewhere.json"))
    assert read_json(path) is None


def test_corrupt_count_mismatch(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d["findings_index"][0].__setitem__("count", 99))
    assert read_json(path) is None


def test_corrupt_missing_sidecar(tmp_path: Path) -> None:
    path = _split(tmp_path)
    (path.parent / "findings" / "trackers.json").unlink()
    assert read_json(path) is None


def test_corrupt_sidecar_category_mismatch(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_sidecar(path, "trackers", lambda d: d.__setitem__("category", "security"))
    assert read_json(path) is None


def test_corrupt_sidecar_report_id_mismatch(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_sidecar(path, "trackers", lambda d: d.__setitem__("report_id", "different"))
    assert read_json(path) is None


def test_corrupt_duplicate_ordinal(tmp_path: Path) -> None:
    path = _split(tmp_path)
    # force the secret sidecar's ordinal to collide with the tracker's
    tracker_ord = json.loads(
        (path.parent / "findings" / "trackers.json").read_text())["findings"][0]["_ordinal"]
    _patch_sidecar(path, "security",
                   lambda d: d["findings"][0].__setitem__("_ordinal", tracker_ord))
    assert read_json(path) is None


def test_corrupt_non_dict_location_returns_none(tmp_path: Path) -> None:
    # a malformed nested location triggers AttributeError in Location.from_dict; swallowed
    path = _split(tmp_path)
    _patch_sidecar(path, "trackers",
                   lambda d: d["findings"][0].__setitem__("locations", ["not-a-dict"]))
    assert read_json(path) is None


def test_corrupt_missing_report_id(tmp_path: Path) -> None:
    # dropping report_id from header + sidecar must not pass via None == None
    path = _split(tmp_path)
    _patch_index(path, lambda d: d.__setitem__("report_id", None))
    _patch_sidecar(path, "trackers", lambda d: d.__setitem__("report_id", None))
    assert read_json(path) is None


def test_corrupt_sparse_ordinal(tmp_path: Path) -> None:
    # mutate one ordinal so the set is no longer 0..n-1 -> reject (would silently reorder)
    path = _split(tmp_path)
    _patch_sidecar(path, "security", lambda d: d["findings"][0].__setitem__("_ordinal", -1))
    assert read_json(path) is None


def test_corrupt_sidecar_own_count_mismatch(tmp_path: Path) -> None:
    # sidecar's own count disagrees with its body (index count left intact) -> reject
    path = _split(tmp_path)
    _patch_sidecar(path, "trackers", lambda d: d.__setitem__("count", 0))
    assert read_json(path) is None


def test_symlinked_findings_dir_refused_on_read(tmp_path: Path) -> None:
    path = _split(tmp_path)
    findings_dir = path.parent / "findings"
    outside = tmp_path / "outside"
    outside.mkdir()
    # move real sidecars out and replace findings/ with a symlink to them
    for p in findings_dir.glob("*.json"):
        p.rename(outside / p.name)
    findings_dir.rmdir()
    findings_dir.symlink_to(outside, target_is_directory=True)
    assert read_json(path) is None


def test_clear_report_does_not_follow_findings_symlink(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "report.json").write_text("{}")
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.json"
    victim.write_text("keep me")
    (reports / "findings").symlink_to(outside, target_is_directory=True)

    from dumpa.core.report import clear_report
    clear_report(reports)

    assert victim.exists()                          # outside file untouched
    assert not (reports / "findings").exists()      # the symlink itself is gone
    assert not (reports / "report.json").exists()


def test_corrupt_missing_sentinel(tmp_path: Path) -> None:
    # a split header without findings:null would be read as empty by an old binary -> refuse
    path = _split(tmp_path)
    _patch_index(path, lambda d: d.pop("findings"))
    assert read_json(path) is None


def test_corrupt_inline_findings_not_null(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d.__setitem__("findings", []))
    assert read_json(path) is None


def test_corrupt_unknown_storage_version(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d.__setitem__("storage_schema_version", 999))
    assert read_json(path) is None


def test_corrupt_unknown_layout(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d.__setitem__("findings_layout", "not-split-v1"))
    assert read_json(path) is None


def test_corrupt_non_dict_index_entry(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d["findings_index"].append("not-a-dict"))
    assert read_json(path) is None


@pytest.mark.parametrize("bad_category", ["../x", "Security", "net work", "a1"])
def test_corrupt_bad_category(tmp_path: Path, bad_category: str) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d["findings_index"][0].__setitem__("category", bad_category))
    assert read_json(path) is None


def test_corrupt_bool_count(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d["findings_index"][0].__setitem__("count", True))
    assert read_json(path) is None


def test_corrupt_bool_ordinal(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_sidecar(path, "trackers", lambda d: d["findings"][0].__setitem__("_ordinal", True))
    assert read_json(path) is None


def test_corrupt_non_dict_sidecar_payload(tmp_path: Path) -> None:
    path = _split(tmp_path)
    (path.parent / "findings" / "trackers.json").write_text(json.dumps(["not", "a", "dict"]))
    assert read_json(path) is None


def test_corrupt_symlinked_sidecar_refused(tmp_path: Path) -> None:
    path = _split(tmp_path)
    sidecar = path.parent / "findings" / "trackers.json"
    target = tmp_path / "elsewhere.json"
    target.write_text(sidecar.read_text())
    sidecar.unlink()
    sidecar.symlink_to(target)
    assert read_json(path) is None


def test_cross_write_sidecar_mismatch(tmp_path: Path) -> None:
    # report.json from write A + a trackers sidecar from write B (different report_id) -> None
    path = _split(tmp_path)
    header_a = path.read_text()
    write_json(_report([_finding("tracker", "AdMob"), _finding("secret", "k"),
                        _finding("dumpcs", "p")]), path)  # write B regenerates sidecars
    path.write_text(header_a)                              # restore A's header (old report_id)
    assert read_json(path) is None


def test_report_json_being_directory_is_none(tmp_path: Path) -> None:
    (tmp_path / "report.json").mkdir()
    assert read_json(tmp_path / "report.json") is None


def test_corrupt_dropped_tail_category(tmp_path: Path) -> None:
    # drop the highest-ordinal category entry + its sidecar: remaining ordinals {0,1} look
    # contiguous, but the header total (3) catches the silent truncation.
    path = _split(tmp_path)               # trackers(0), security(1), patterns(2)
    (path.parent / "findings" / "patterns.json").unlink()
    _patch_index(path, lambda d: d.__setitem__(
        "findings_index", [e for e in d["findings_index"] if e["category"] != "patterns"]))
    assert read_json(path) is None


def test_corrupt_findings_total_mismatch(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d.__setitem__("findings_total", 99))
    assert read_json(path) is None


def test_corrupt_findings_total_missing(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_index(path, lambda d: d.pop("findings_total"))
    assert read_json(path) is None


def test_corrupt_unreferenced_sidecar(tmp_path: Path) -> None:
    # an extra valid-looking sidecar not named in the index is corruption
    path = _split(tmp_path)
    stale = json.loads((path.parent / "findings" / "trackers.json").read_text())
    stale["category"] = "engine"
    (path.parent / "findings" / "engine.json").write_text(json.dumps(stale))
    assert read_json(path) is None


def test_corrupt_non_dict_finding_item(tmp_path: Path) -> None:
    path = _split(tmp_path)
    _patch_sidecar(path, "trackers", lambda d: d["findings"].__setitem__(0, "not-a-dict"))
    assert read_json(path) is None


def test_corrupt_swapped_ordinals_between_sidecars(tmp_path: Path) -> None:
    # swap _ordinal between two sidecars; header-declared ordinals catch the silent reorder
    path = _split(tmp_path)                       # trackers(0), security(1), patterns(2)
    _patch_sidecar(path, "trackers", lambda d: d["findings"][0].__setitem__("_ordinal", 1))
    _patch_sidecar(path, "security", lambda d: d["findings"][0].__setitem__("_ordinal", 0))
    assert read_json(path) is None


def test_corrupt_header_ordinals_tampered(tmp_path: Path) -> None:
    path = _split(tmp_path)
    # claim trackers owns ordinal 1 (which actually belongs to security) -> mismatch
    def bump(d):
        for e in d["findings_index"]:
            if e["category"] == "trackers":
                e["ordinals"] = [1]
    _patch_index(path, bump)
    assert read_json(path) is None


def test_corrupt_category_trailing_newline(tmp_path: Path) -> None:
    path = _split(tmp_path)
    def rename(d):
        e = d["findings_index"][0]
        e["category"] = "trackers\n"
        e["file"] = "findings/trackers\n.json"
    _patch_index(path, rename)
    assert read_json(path) is None


def test_huge_findings_total_is_rejected_without_oom(tmp_path: Path) -> None:
    # an attacker-set findings_total must not materialize set(range(total))
    path = _write(tmp_path, _report([]))          # empty: index [], total 0
    _patch_index(path, lambda d: d.__setitem__("findings_total", 10 ** 9))
    assert read_json(path) is None


def test_write_json_recovers_when_sidecar_is_directory(tmp_path: Path) -> None:
    # a stray reports/findings/trackers.json *directory* must not strand the old report
    reports = tmp_path / "reports"
    write_json(_report([_finding("tracker", "AdMob")]), reports / "report.json")
    sidecar = reports / "findings" / "trackers.json"
    sidecar.unlink()
    sidecar.mkdir()
    (sidecar / "junk").write_text("non-empty dir")          # corruption in our namespace

    write_json(_report([_finding("secret", "k")]), reports / "report.json")

    assert (reports / "report.json").is_file()
    assert not (reports / "findings" / "trackers.json").exists()  # stale dir cleared
    assert read_json(reports / "report.json") is not None


def test_write_json_recovers_when_findings_is_regular_file(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "report.json").write_text("{}")
    (reports / "findings").write_text("i am a file, not a dir")   # stray artifact

    write_json(_report([_finding("tracker", "AdMob")]), reports / "report.json")

    findings_dir = reports / "findings"
    assert findings_dir.is_dir()                                  # replaced with a real dir
    assert (findings_dir / "trackers.json").is_file()
    assert read_json(reports / "report.json") is not None


def test_write_json_does_not_write_through_findings_symlink(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (reports / "findings").symlink_to(outside, target_is_directory=True)

    write_json(_report([_finding("tracker", "AdMob")]), reports / "report.json")

    assert not list(outside.glob("*.json"))         # nothing escaped into outside/
    findings_dir = reports / "findings"
    assert not findings_dir.is_symlink() and findings_dir.is_dir()
    assert (findings_dir / "trackers.json").is_file()
    assert read_json(reports / "report.json") is not None
