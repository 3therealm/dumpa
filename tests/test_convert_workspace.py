"""convert's reusable-workspace path: reuse vs rebuild, apk emission, build options.

The apktool merge itself is verified manually (needs real tools); these cover the new
orchestration around it — the decide-reuse branch and the copy-out — with build_workspace
stubbed so no external tool is touched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.convert import pipeline
from dumpa.convert.pipeline import _emit_apk, convert_into_workspace, workspace_build_options
from dumpa.core.tools import build_default_registry
from dumpa.core.workspace import Workspace, make_meta

_SHA = "a" * 64
_REG = build_default_registry()
_UNSIGNED = {"xapk_signing": "unsigned"}


def _populated_ws(tmp_path: Path, *, sha: str = _SHA,
                  build_options: dict[str, str] | None = None) -> Workspace:
    """A workspace that decide_reuse will accept: marker + non-empty extracted/ + app.apk."""
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    (ws.extracted_dir / "AndroidManifest.xml").write_bytes(b"x")
    ws.app_apk.write_bytes(b"PK\x03\x04")
    ws.write_meta(make_meta(
        input_path=Path("app.xapk"), input_sha256=sha, input_size=1,
        input_type="xapk", tool_versions={}, build_options=build_options or dict(_UNSIGNED),
    ))
    return ws


# --- convert_into_workspace: reuse vs rebuild --------------------------------

def test_reuses_unchanged_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _populated_ws(tmp_path)
    monkeypatch.setattr(pipeline, "read_package", lambda reg, apk: "com.example")

    def _must_not_build(*a: object, **k: object) -> None:
        raise AssertionError("build_workspace called on an unchanged workspace")

    monkeypatch.setattr(pipeline, "build_workspace", _must_not_build)
    apk, pkg = convert_into_workspace(
        _REG, ws, Path("app.xapk"), _SHA, None, dict(_UNSIGNED), force=False)
    assert apk == ws.app_apk
    assert pkg == "com.example"


def test_builds_when_workspace_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = Workspace(root=tmp_path / "ws")  # not created -> decide_reuse builds
    monkeypatch.setattr(pipeline, "read_package", lambda reg, apk: None)
    calls: list[str] = []
    monkeypatch.setattr(pipeline, "build_workspace",
                        lambda *a, **k: calls.append("built"))
    apk, pkg = convert_into_workspace(
        _REG, ws, Path("app.xapk"), _SHA, None, dict(_UNSIGNED), force=False)
    assert calls == ["built"]
    assert apk == ws.app_apk
    assert pkg is None


def test_force_rebuilds_matching_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _populated_ws(tmp_path)
    monkeypatch.setattr(pipeline, "read_package", lambda reg, apk: None)
    calls: list[str] = []
    monkeypatch.setattr(pipeline, "build_workspace",
                        lambda *a, **k: calls.append("built"))
    convert_into_workspace(_REG, ws, Path("app.xapk"), _SHA, None, dict(_UNSIGNED), force=True)
    assert calls == ["built"]


# --- _emit_apk: copies, leaving the workspace's app.apk intact ---------------

def test_emit_apk_copies_without_moving(tmp_path: Path) -> None:
    src = tmp_path / "app.apk"
    src.write_bytes(b"apkdata")
    out = tmp_path / "out"
    out.mkdir()
    dst = _emit_apk(src, out, "myapp")
    assert dst == out / "myapp.apk"
    assert dst.read_bytes() == b"apkdata"
    assert src.exists()                         # source survives (copy, not rename)


def test_emit_apk_overwrites_existing_file(tmp_path: Path) -> None:
    src = tmp_path / "app.apk"
    src.write_bytes(b"new")
    out = tmp_path / "out"
    out.mkdir()
    (out / "myapp.apk").write_bytes(b"stale")
    dst = _emit_apk(src, out, "myapp")
    assert dst.read_bytes() == b"new"


def test_emit_apk_refuses_directory_target(tmp_path: Path) -> None:
    src = tmp_path / "app.apk"
    src.write_bytes(b"x")
    out = tmp_path / "out"
    (out / "myapp.apk").mkdir(parents=True)
    with pytest.raises(Exception, match="refusing to overwrite directory"):
        _emit_apk(src, out, "myapp")


# --- workspace_build_options -------------------------------------------------

def test_build_options_apk_is_none() -> None:
    assert workspace_build_options("apk", None) is None


def test_build_options_xapk_unsigned() -> None:
    assert workspace_build_options("xapk", None) == {"xapk_signing": "unsigned"}
