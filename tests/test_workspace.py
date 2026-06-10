"""Workspace marker round-trip and decide_reuse policy (O5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.core.errors import DumpaError
from dumpa.core.workspace import Workspace, decide_reuse, make_meta


def _populate(root: Path, sha: str) -> Workspace:
    """Build a populated workspace: marker + a non-empty extracted dir."""
    ws = Workspace(root=root)
    ws.prepare_build()
    (ws.extracted_dir / "AndroidManifest.xml").write_bytes(b"\x00")
    ws.write_meta(make_meta(
        input_path=root / "in.apk", input_sha256=sha, input_size=10,
        input_type="apk", tool_versions={"aapt": "x"},
    ))
    return ws


def _populate_with_options(root: Path, sha: str, options: dict[str, str]) -> Workspace:
    """Build a populated workspace with explicit build options."""
    ws = Workspace(root=root)
    ws.prepare_build()
    (ws.extracted_dir / "AndroidManifest.xml").write_bytes(b"\x00")
    ws.write_meta(make_meta(
        input_path=root / "in.xapk", input_sha256=sha, input_size=10,
        input_type="xapk", tool_versions={"aapt": "x"}, build_options=options,
    ))
    return ws


def test_meta_roundtrip(tmp_path: Path) -> None:
    ws = _populate(tmp_path / "ws", "a" * 64)
    meta = ws.read_meta()
    assert meta is not None
    assert meta.input_sha256 == "a" * 64
    assert meta.input_type == "apk"
    assert meta.tool_versions == {"aapt": "x"}
    assert meta.optional_scanners == ()
    assert ws.is_populated()


def test_meta_roundtrip_optional_scanners(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    ws.prepare_build()
    ws.write_meta(make_meta(
        input_path=tmp_path / "in.apk", input_sha256="a" * 64, input_size=10,
        input_type="apk", tool_versions={}, optional_scanners=("native_r2",),
    ))
    meta = ws.read_meta()
    assert meta is not None
    assert meta.optional_scanners == ("native_r2",)


def test_legacy_meta_without_optional_scanners_defaults_empty(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    ws.prepare_build()
    ws.meta_path.write_text(
        """{
  "schema_version": 1,
  "dumpa_version": "0.1.0",
  "input_path": "in.apk",
  "input_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "input_size": 10,
  "input_type": "apk",
  "created": "2026-01-01T00:00:00+00:00",
  "tool_versions": {},
  "build_options": {}
}
""",
        encoding="UTF-8",
    )
    meta = ws.read_meta()
    assert meta is not None
    assert meta.optional_scanners == ()


def test_reuse_when_sha_matches(tmp_path: Path) -> None:
    ws = _populate(tmp_path / "ws", "a" * 64)
    assert decide_reuse(ws, "a" * 64, force=False) is True


def test_force_forces_rebuild(tmp_path: Path) -> None:
    ws = _populate(tmp_path / "ws", "a" * 64)
    assert decide_reuse(ws, "a" * 64, force=True) is False


def test_sha_mismatch_raises(tmp_path: Path) -> None:
    ws = _populate(tmp_path / "ws", "a" * 64)
    with pytest.raises(DumpaError, match="different input"):
        decide_reuse(ws, "b" * 64, force=False)


def test_absent_workspace_builds(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "fresh")
    assert decide_reuse(ws, "a" * 64, force=False) is False


def test_nonworkspace_dir_refuses(tmp_path: Path) -> None:
    root = tmp_path / "dirty"
    root.mkdir()
    (root / "random.txt").write_text("hi")
    ws = Workspace(root=root)
    with pytest.raises(DumpaError, match="not a dumpa workspace"):
        decide_reuse(ws, "a" * 64, force=False)


def test_marker_present_but_unpopulated_rebuilds(tmp_path: Path) -> None:
    ws = _populate(tmp_path / "ws", "a" * 64)
    # Empty the extraction but keep the marker: must rebuild, not reuse.
    (ws.extracted_dir / "AndroidManifest.xml").unlink()
    assert decide_reuse(ws, "a" * 64, force=False) is False


def test_reuse_when_build_options_match(tmp_path: Path) -> None:
    options = {"xapk_signing": "unsigned"}
    ws = _populate_with_options(tmp_path / "ws", "a" * 64, options)
    assert decide_reuse(ws, "a" * 64, force=False, build_options=options) is True


def test_build_option_mismatch_raises(tmp_path: Path) -> None:
    ws = _populate_with_options(tmp_path / "ws", "a" * 64, {"xapk_signing": "unsigned"})
    with pytest.raises(DumpaError, match="different build options"):
        decide_reuse(ws, "a" * 64, force=False, build_options={"xapk_signing": "signed"})
