"""`dumpa scan-native` command: bare ELF scan, radare2 deep path, fail-soft."""

from __future__ import annotations

from pathlib import Path

import pytest
from _elf_build import build_elf

from dumpa.commands import scan_native as cmd
from dumpa.core.errors import DumpaError, ToolNotFoundError
from dumpa.core.r2 import R2Analysis, R2Function, R2Section
from dumpa.core.workspace import Workspace, make_meta


def _ws_dir(tmp_path: Path) -> Path:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    so = ws.extracted_dir / "lib" / "arm64-v8a" / "libfoo.so"
    so.parent.mkdir(parents=True)
    elf, _ = build_elf()
    so.write_bytes(elf)
    ws.write_meta(make_meta(input_path=Path("a.apk"), input_sha256="a" * 64,
                            input_size=len(elf), input_type="apk", tool_versions={}))
    return ws.root


class _Tool:
    version = "radare2 5.9.0"


class _Reg:
    def __init__(self, *, absent: bool = False) -> None:
        self._absent = absent

    def resolve(self, name: str) -> _Tool:
        if self._absent:
            raise ToolNotFoundError("radare2 not found")
        return _Tool()


def _patch_r2(monkeypatch, *, absent: bool = False) -> None:
    monkeypatch.setattr(cmd.native_r2, "build_default_registry", lambda _p: _Reg(absent=absent))
    monkeypatch.setattr(cmd.native_r2, "load_config",
                        lambda: type("C", (), {"tool_paths": {}})())
    monkeypatch.setattr(cmd.native_r2.r2, "analyze", lambda _p, version=None: R2Analysis(
        version="radare2 5.9.0", functions=[R2Function("f", 0x10, 8, 1)],
        sections=[R2Section(".text", 0x1000, 0x400, 2048, "-r-x", 7.95)]))


def test_bare_scan_prints_elf(tmp_path: Path, capsys) -> None:
    cmd.scan_native(_ws_dir(tmp_path))
    out = capsys.readouterr().out
    assert "libfoo.so" in out
    assert "native" in out
    assert "native-region" not in out          # no deep path without --tool


def test_radare2_path_adds_regions(tmp_path: Path, capsys, monkeypatch) -> None:
    _patch_r2(monkeypatch)
    cmd.scan_native(_ws_dir(tmp_path), tool="radare2")
    out = capsys.readouterr().out
    assert "native-region" in out
    assert "packed" in out


def test_radare2_absent_still_prints_elf(tmp_path: Path, capsys, monkeypatch) -> None:
    _patch_r2(monkeypatch, absent=True)
    cmd.scan_native(_ws_dir(tmp_path), tool="radare2")
    out = capsys.readouterr().out
    assert "libfoo.so" in out                  # ELF results survive
    assert "native-region" not in out          # deep path skipped


def test_unsupported_tool_raises(tmp_path: Path) -> None:
    with pytest.raises(DumpaError):
        cmd.scan_native(_ws_dir(tmp_path), tool="ghidra")


def test_non_workspace_dir_raises(tmp_path: Path) -> None:
    bare = tmp_path / "empty"
    bare.mkdir()
    with pytest.raises(DumpaError):
        cmd.scan_native(bare)
