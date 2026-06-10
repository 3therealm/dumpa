"""`dumpa scan-trackers` / `dumpa scan-protections`: focused, report-less scans."""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.commands import scan as cmd
from dumpa.core.errors import DumpaError
from dumpa.core.workspace import Workspace, make_meta


def _ws_dir(tmp_path: Path, files: dict[str, bytes]) -> Path:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    for rel, data in files.items():
        p = ws.extracted_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    ws.write_meta(make_meta(input_path=Path("a.apk"), input_sha256="a" * 64,
                            input_size=1, input_type="apk", tool_versions={}))
    return ws.root


def test_scan_trackers_detects_firebase(tmp_path: Path, capsys) -> None:
    target = _ws_dir(tmp_path, {"classes.dex": b"junk Lcom/google/firebase/analytics; junk"})
    cmd.scan_trackers(target)
    out = capsys.readouterr().out
    assert "Firebase Analytics" in out
    assert "Google" in out                     # the `owner` salient column


def test_scan_protections_detects_packer(tmp_path: Path, capsys) -> None:
    target = _ws_dir(tmp_path, {"lib/arm64-v8a/libjiagu.so": b"\x7fELF packed"})
    cmd.scan_protections(target)
    out = capsys.readouterr().out
    assert "Jiagu" in out
    assert "packer" in out                     # the `category` salient column


def test_scan_trackers_clean_prints_none(tmp_path: Path, capsys) -> None:
    target = _ws_dir(tmp_path, {"classes.dex": b"nothing interesting here"})
    cmd.scan_trackers(target)
    assert "no tracker findings" in capsys.readouterr().out


def test_scan_trackers_non_workspace_dir_raises(tmp_path: Path) -> None:
    bare = tmp_path / "empty"
    bare.mkdir()
    with pytest.raises(DumpaError):
        cmd.scan_trackers(bare)


def test_scan_protections_non_workspace_dir_raises(tmp_path: Path) -> None:
    bare = tmp_path / "empty"
    bare.mkdir()
    with pytest.raises(DumpaError):
        cmd.scan_protections(bare)
