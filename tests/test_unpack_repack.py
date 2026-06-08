"""commands.unpack / commands.repack: orchestration around the apktool decode/build.

The apktool decode/build themselves need real tools and are verified manually; these
cover the new command logic — decode gating, reuse, and the repack guards — with the
heavy steps stubbed so no external tool is touched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.commands import repack as repack_cmd
from dumpa.commands import unpack as unpack_cmd
from dumpa.core.errors import DumpaError
from dumpa.core.workspace import Workspace, make_meta

_SHA = "a" * 64


class _FakeTool:
    pass


class _FakeRegistry:
    """Stand-in registry: resolve/require never hit PATH."""

    def resolve(self, name: str) -> _FakeTool:
        return _FakeTool()

    def require(self, *names: str) -> None:
        return None


def _make_input(tmp_path: Path) -> Path:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04input")
    return apk


def _populated_ws(root: Path, *, smali: bool = False) -> Workspace:
    ws = Workspace(root=root)
    ws.extracted_dir.mkdir(parents=True)
    (ws.extracted_dir / "AndroidManifest.xml").write_bytes(b"x")
    ws.app_apk.write_bytes(b"PK\x03\x04")
    if smali:
        ws.smali_dir.mkdir(parents=True)
        (ws.smali_dir / "apktool.yml").write_text("v: 2\n")
    ws.write_meta(make_meta(
        input_path=Path("app.apk"), input_sha256=_SHA, input_size=1,
        input_type="apk", tool_versions={},
    ))
    return ws


# --- unpack ------------------------------------------------------------------

def test_unpack_builds_and_decodes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    apk = _make_input(tmp_path)
    ws_dir = tmp_path / "ws"
    monkeypatch.setattr(unpack_cmd, "build_default_registry", lambda paths: _FakeRegistry())

    def _build(registry, ws, input_abs, in_type, sha, sign, opts):
        _populated_ws(ws.root)

    decoded: list[Path] = []

    def _decode(tool, apk_path, out_dir):
        out_dir.mkdir(parents=True)
        (out_dir / "apktool.yml").write_text("v: 2\n")
        decoded.append(out_dir)

    monkeypatch.setattr(unpack_cmd, "build_workspace", _build)
    monkeypatch.setattr(unpack_cmd.apktool, "decode_apk", _decode)

    unpack_cmd.unpack(apk, workspace=ws_dir)

    ws = Workspace(root=ws_dir)
    assert ws.has_smali()
    assert decoded == [ws.smali_dir]


def test_unpack_no_decode_skips_smali(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    apk = _make_input(tmp_path)
    ws_dir = tmp_path / "ws"
    monkeypatch.setattr(unpack_cmd, "build_default_registry", lambda paths: _FakeRegistry())
    monkeypatch.setattr(unpack_cmd, "build_workspace",
                        lambda *a, **k: _populated_ws(ws_dir))

    def _must_not_decode(*a: object, **k: object) -> None:
        raise AssertionError("decode_apk called with --no-decode")

    monkeypatch.setattr(unpack_cmd.apktool, "decode_apk", _must_not_decode)

    unpack_cmd.unpack(apk, workspace=ws_dir, decode=False)
    assert not Workspace(root=ws_dir).has_smali()


def test_unpack_reuses_unchanged_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    apk = _make_input(tmp_path)
    ws_dir = tmp_path / "ws"
    # Pre-populate a workspace whose sha matches this input so decide_reuse accepts it.
    ws = _populated_ws(ws_dir, smali=True)
    real_sha = __import__("dumpa.core.hashing", fromlist=["sha256_file"]).sha256_file(apk)
    ws.write_meta(make_meta(
        input_path=apk, input_sha256=real_sha, input_size=apk.stat().st_size,
        input_type="apk", tool_versions={}))
    monkeypatch.setattr(unpack_cmd, "build_default_registry", lambda paths: _FakeRegistry())

    def _must_not_build(*a: object, **k: object) -> None:
        raise AssertionError("build_workspace called on an unchanged workspace")

    monkeypatch.setattr(unpack_cmd, "build_workspace", _must_not_build)
    # smali already present -> decode must be skipped
    monkeypatch.setattr(unpack_cmd.apktool, "decode_apk",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("re-decoded")))

    unpack_cmd.unpack(apk, workspace=ws_dir)  # must not raise


# --- repack ------------------------------------------------------------------

def test_repack_rejects_non_workspace(tmp_path: Path) -> None:
    bare = tmp_path / "nope"
    bare.mkdir()
    with pytest.raises(DumpaError, match="not a dumpa workspace"):
        repack_cmd.repack(bare)


def test_repack_rejects_missing_smali(tmp_path: Path) -> None:
    ws = _populated_ws(tmp_path / "ws", smali=False)
    with pytest.raises(DumpaError, match="no decoded smali tree"):
        repack_cmd.repack(ws.root)


def test_repack_invokes_pack_align_sign(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _populated_ws(tmp_path / "ws", smali=True)
    monkeypatch.setattr(repack_cmd, "build_default_registry", lambda paths: _FakeRegistry())
    monkeypatch.setattr(repack_cmd, "resolve_signing", lambda preset, config, registry: None)

    calls: list[tuple[Path, Path]] = []

    def _pack(registry, apk_dir, out, sign):
        calls.append((apk_dir, out))
        return out

    monkeypatch.setattr(repack_cmd, "pack_align_sign", _pack)

    out = tmp_path / "patched.apk"
    repack_cmd.repack(ws.root, out=out)
    assert calls == [(ws.smali_dir, out)]
