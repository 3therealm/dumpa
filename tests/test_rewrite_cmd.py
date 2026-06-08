"""commands.rewrite: orchestration around the smali find-and-replace engine.

The engine itself is covered by test_rewrite.py; these cover the command wiring —
workspace guards, the preview-vs-apply gate, report recording, and the --rebuild hand-off
— with external tools stubbed so nothing on PATH is touched.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

from dumpa.commands import rewrite as rewrite_cmd
from dumpa.commands.analyze import const_file_report_json
from dumpa.core.errors import DumpaError
from dumpa.core.report import read_json
from dumpa.core.workspace import Workspace, make_meta

_SHA = "a" * 64

_REWRITE_TOML = """
[bundle]
name = "redirect-analytics"
version = "2026.06.1"
updated = "2026-06-08"

[[rule]]
kind = "rewrite"
subject = "point analytics host at localhost"
category = "endpoints"
confidence = "medium"
regex = ['(const-string [vp]\\d+, ")analytics\\.example\\.com(")']
replace = '\\g<1>127.0.0.1\\g<2>'
"""


class _FakeRegistry:
    def resolve(self, name: str) -> object:
        return object()

    def require(self, *names: str) -> None:
        return None


class _FakeConfig:
    tool_paths: ClassVar[dict[str, str]] = {}


def _ws_with_smali(root: Path) -> Workspace:
    ws = Workspace(root=root)
    ws.extracted_dir.mkdir(parents=True)
    ws.app_apk.write_bytes(b"PK\x03\x04")
    ws.smali_dir.mkdir(parents=True)
    (ws.smali_dir / "Foo.smali").write_text(
        'const-string v0, "analytics.example.com"\n', encoding="latin-1")
    ws.write_meta(make_meta(
        input_path=Path("app.apk"), input_sha256=_SHA, input_size=1,
        input_type="apk", tool_versions={}))
    return ws


def _bundle_file(tmp_path: Path) -> Path:
    path = tmp_path / "rules.toml"
    path.write_text(_REWRITE_TOML, encoding="UTF-8")
    return path


@pytest.fixture(autouse=True)
def _stub_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rewrite_cmd, "build_default_registry", lambda paths: _FakeRegistry())
    monkeypatch.setattr(rewrite_cmd, "load_config", lambda: _FakeConfig())


def test_rejects_non_workspace(tmp_path: Path) -> None:
    bare = tmp_path / "nope"
    bare.mkdir()
    with pytest.raises(DumpaError, match="not a dumpa workspace"):
        rewrite_cmd.rewrite(bare, pattern=_bundle_file(tmp_path))


def test_preview_only_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ws = _ws_with_smali(tmp_path / "ws")
    bundle = _bundle_file(tmp_path)
    rewrite_cmd.rewrite(ws.root, pattern=bundle)
    # smali untouched, no report written
    assert "analytics.example.com" in (ws.smali_dir / "Foo.smali").read_text(encoding="latin-1")
    assert not (ws.reports_dir / const_file_report_json).exists()
    assert "[1]" in capsys.readouterr().out


def test_replace_without_select_is_preview(tmp_path: Path) -> None:
    ws = _ws_with_smali(tmp_path / "ws")
    bundle = _bundle_file(tmp_path)
    rewrite_cmd.rewrite(ws.root, pattern=bundle, replace=bundle)  # no --select
    assert "analytics.example.com" in (ws.smali_dir / "Foo.smali").read_text(encoding="latin-1")
    assert not (ws.reports_dir / const_file_report_json).exists()


def test_apply_writes_findings(tmp_path: Path) -> None:
    ws = _ws_with_smali(tmp_path / "ws")
    bundle = _bundle_file(tmp_path)
    rewrite_cmd.rewrite(ws.root, pattern=bundle, replace=bundle, select="all")
    assert "127.0.0.1" in (ws.smali_dir / "Foo.smali").read_text(encoding="latin-1")
    report = read_json(ws.reports_dir / const_file_report_json)
    assert report is not None
    rewrites = [f for f in report.findings if f.kind == "rewrite"]
    assert len(rewrites) == 1
    assert rewrites[0].attributes["action"] == "applied"
    assert rewrites[0].attributes["category"] == "endpoints"


def test_apply_invokes_rebuild(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _ws_with_smali(tmp_path / "ws")
    bundle = _bundle_file(tmp_path)
    monkeypatch.setattr(rewrite_cmd, "resolve_signing", lambda preset, config, registry: None)
    calls: list[tuple[Path, Path]] = []
    monkeypatch.setattr(rewrite_cmd, "pack_align_sign",
                        lambda registry, apk_dir, out, sign: calls.append((apk_dir, out)))
    out = tmp_path / "patched.apk"
    rewrite_cmd.rewrite(ws.root, pattern=bundle, replace=bundle, select="all",
                        rebuild=True, out=out)
    assert calls == [(ws.smali_dir, out)]


def test_auto_decode_when_no_smali(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    ws.app_apk.write_bytes(b"PK\x03\x04")
    ws.write_meta(make_meta(
        input_path=Path("app.apk"), input_sha256=_SHA, input_size=1,
        input_type="apk", tool_versions={}))

    decoded: list[Path] = []

    def _fake_decode(tool: object, apk: Path, out_dir: Path) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "Foo.smali").write_text(
            'const-string v0, "analytics.example.com"\n', encoding="latin-1")
        decoded.append(out_dir)

    monkeypatch.setattr(rewrite_cmd.apktool, "decode_apk", _fake_decode)
    rewrite_cmd.rewrite(ws.root, pattern=_bundle_file(tmp_path))
    assert decoded == [ws.smali_dir]
