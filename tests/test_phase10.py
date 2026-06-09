"""Diff, blocklist export, and clean."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from dumpa.commands.clean import clean
from dumpa.core.diff import (
    MethodDelta,
    diff_native_symbols,
    diff_reports,
    diff_unity_methods,
    render_diff,
    render_native_symbol_diff,
    render_unity_method_diff,
)
from dumpa.core.errors import DumpaError
from dumpa.core.report import (
    AppFacts,
    Confidence,
    Finding,
    Report,
    render_blocklist,
    report_domains,
)
from dumpa.core.workspace import Workspace, make_meta


def _report(*findings: Finding, engine: str | None = None) -> Report:
    return Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024, engine=engine),
        findings=list(findings),
    )


def _tracker(subject: str) -> Finding:
    return Finding(kind="tracker", subject=subject, confidence=Confidence.HIGH)


def _tracker_owned(subject: str, owner: str) -> Finding:
    return Finding(kind="tracker", subject=subject, confidence=Confidence.HIGH,
                   attributes={"owner": owner})


# --- diff --------------------------------------------------------------------

def test_diff_added_and_removed() -> None:
    old = _report(_tracker("AdMob"), _tracker("Flurry"), engine="Unity")
    new = _report(_tracker("AdMob"), _tracker("AppLovin MAX"), engine="Unity")
    d = diff_reports(old, new)
    assert not d.engine_changed
    delta = next(x for x in d.deltas if x.kind == "tracker")
    assert delta.added == ["AppLovin MAX"]
    assert delta.removed == ["Flurry"]


def test_diff_engine_change_and_render() -> None:
    d = diff_reports(_report(engine="Unity"), _report(engine="Godot"))
    assert d.engine_changed
    text = render_diff("a", "b", d)
    assert "engine: Unity -> Godot" in text


def test_diff_no_changes() -> None:
    same = _report(_tracker("AdMob"), engine="Unity")
    d = diff_reports(same, _report(_tracker("AdMob"), engine="Unity"))
    assert not d.changed


def test_diff_companies_added_removed() -> None:
    old = _report(_tracker_owned("AdMob", "Google"))
    new = _report(_tracker_owned("AdMob", "Google"), _tracker_owned("AppLovin MAX", "Meta"))
    d = diff_reports(old, new)
    assert d.companies_added == ["Meta"]
    assert d.companies_removed == []


def test_diff_company_only_change_is_changed() -> None:
    # identical tracker subject; only the owner attribute differs -> subject deltas empty,
    # but the company set changed, so .changed must be True.
    old = _report(_tracker_owned("AdMob", "Google"))
    new = _report(_tracker_owned("AdMob", "Meta"))
    d = diff_reports(old, new)
    assert all(not delta.changed for delta in d.deltas)
    assert d.companies_added == ["Meta"]
    assert d.companies_removed == ["Google"]
    assert d.changed


def test_render_diff_companies_block() -> None:
    old = _report(_tracker_owned("AdMob", "Google"))
    new = _report(_tracker_owned("AdMob", "Meta"))
    text = render_diff("a", "b", diff_reports(old, new))
    assert "## companies" in text
    assert "  + Meta" in text
    assert "  - Google" in text
    assert "no finding changes" not in text


# --- native symbol diff ------------------------------------------------------

def _sidecar(ws: Workspace, abi: str, lib: str,
             exports: list[str], imports: list[str]) -> None:
    """Mirror scanners.native: file '<abi>__<lib>.json', JSON 'lib' is the bare so name."""
    ws.native_dir.mkdir(parents=True, exist_ok=True)
    (ws.native_dir / f"{abi}__{lib}.json").write_text(json.dumps({
        "abi": abi, "lib": lib,
        "exports": [{"name": n} for n in exports],
        "imports": [{"name": n} for n in imports],
    }))


def test_native_symbol_diff(tmp_path: Path) -> None:
    old = Workspace(root=tmp_path / "old")
    new = Workspace(root=tmp_path / "new")
    _sidecar(old, "arm64-v8a", "libgame.so", ["common", "gone"], ["dlopen"])
    _sidecar(new, "arm64-v8a", "libgame.so", ["common", "fresh"], ["dlopen", "malloc"])
    _sidecar(new, "arm64-v8a", "libinjected.so", ["DobbyHook"], [])

    deltas = {d.lib: d for d in diff_native_symbols(old, new)}
    game = deltas["arm64-v8a/libgame.so"]
    assert game.exports_added == ["fresh"]
    assert game.exports_removed == ["gone"]
    assert game.imports_added == ["malloc"]
    assert game.imports_removed == []
    injected = deltas["arm64-v8a/libinjected.so"]
    assert injected.exports_added == ["DobbyHook"]


def test_native_symbol_diff_no_change(tmp_path: Path) -> None:
    old = Workspace(root=tmp_path / "old")
    new = Workspace(root=tmp_path / "new")
    _sidecar(old, "arm64-v8a", "lib.so", ["a"], ["b"])
    _sidecar(new, "arm64-v8a", "lib.so", ["a"], ["b"])
    assert diff_native_symbols(old, new) == []
    assert render_native_symbol_diff([]) == ""


def test_native_symbol_diff_render(tmp_path: Path) -> None:
    old = Workspace(root=tmp_path / "old")
    new = Workspace(root=tmp_path / "new")
    _sidecar(old, "arm64-v8a", "lib.so", [], [])
    _sidecar(new, "arm64-v8a", "lib.so", ["DobbyHook"], [])
    text = render_native_symbol_diff(diff_native_symbols(old, new))
    assert "## native symbols" in text
    assert "arm64-v8a/lib.so" in text
    assert "+ DobbyHook" in text


# --- unity method diff -------------------------------------------------------

def _dumpcs(ws: Workspace, body: str) -> None:
    ws.dumps_dir.mkdir(parents=True, exist_ok=True)
    (ws.dumps_dir / "dump.cs").write_text(body, encoding="utf-8")


def test_unity_method_diff_missing_dumpcs(tmp_path: Path) -> None:
    old = Workspace(root=tmp_path / "old")
    new = Workspace(root=tmp_path / "new")
    _dumpcs(new, "public class C\n{\n\tpublic void M() { }\n}\n")
    # old has no dump.cs -> None, and the renderer shows the skip note.
    assert diff_unity_methods(old, new) is None
    assert "run analyze first" in render_unity_method_diff(None)


def test_unity_method_diff_changes(tmp_path: Path) -> None:
    old = Workspace(root=tmp_path / "old")
    new = Workspace(root=tmp_path / "new")
    _dumpcs(old, "public class C\n{\n\tpublic void Old() { }\n}\n")
    _dumpcs(new, "public class C\n{\n\tpublic void New() { }\n}\n")
    delta = diff_unity_methods(old, new)
    assert delta is not None
    assert delta.added == ["C::public void New()"]
    assert delta.removed == ["C::public void Old()"]


def test_unity_method_render_unchanged_is_empty() -> None:
    assert render_unity_method_diff(MethodDelta()) == ""


# --- blocklist ---------------------------------------------------------------

def test_report_domains_and_blocklist() -> None:
    report = _report(
        Finding(kind="endpoint", subject="ads.example.com", confidence=Confidence.LOW),
        Finding(kind="endpoint", subject="cdn.example.org", confidence=Confidence.LOW),
    )
    assert report_domains(report) == ["ads.example.com", "cdn.example.org"]
    assert render_blocklist(report, "hosts") == "0.0.0.0 ads.example.com\n0.0.0.0 cdn.example.org\n"
    assert render_blocklist(report, "adguard") == "||ads.example.com^\n||cdn.example.org^\n"


def test_blocklist_empty() -> None:
    assert render_blocklist(_report(), "hosts") == ""


# --- clean -------------------------------------------------------------------

def _make_workspace(root: Path) -> Workspace:
    ws = Workspace(root=root)
    ws.prepare_build()
    ws.write_meta(make_meta(
        input_path=root / "in.apk", input_sha256="c" * 64, input_size=1,
        input_type="apk", tool_versions={},
    ))
    return ws


def test_clean_removes_workspace(tmp_path: Path) -> None:
    ws = _make_workspace(tmp_path / "ws")
    clean(ws.root)
    assert not ws.root.exists()


def test_clean_refuses_non_workspace(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "important.txt").write_text("keep me")
    with pytest.raises(DumpaError, match="not a dumpa workspace"):
        clean(plain)
    assert plain.exists()
    shutil.rmtree(plain)
