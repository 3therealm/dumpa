"""reporting.build_report + JSON file round-trip on a synthetic workspace."""

from __future__ import annotations

import zipfile
from pathlib import Path

from dumpa.core.report import read_json, write_json
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


def test_report_json_file_round_trip(tmp_path: Path) -> None:
    ws = _workspace(tmp_path / "ws")
    report = build_report(build_default_registry(), ws)
    path = ws.reports_dir / "report.json"
    write_json(report, path)
    assert path.is_file()
    assert read_json(path) == report


def test_read_json_missing_is_none(tmp_path: Path) -> None:
    assert read_json(tmp_path / "nope.json") is None
