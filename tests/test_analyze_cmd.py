"""`dumpa analyze` metadata helpers."""

from __future__ import annotations

from pathlib import Path

from dumpa.commands.analyze import _merge_optional_scanners
from dumpa.core.workspace import Workspace, make_meta


def test_merge_optional_scanners_persists_request(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    ws.prepare_build()
    ws.write_meta(make_meta(
        input_path=Path("a.apk"), input_sha256="a" * 64, input_size=1,
        input_type="apk", tool_versions={},
    ))

    _merge_optional_scanners(ws, ("native_r2",))

    meta = ws.read_meta()
    assert meta is not None
    assert meta.optional_scanners == ("native_r2",)


def test_merge_optional_scanners_preserves_existing_order(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    ws.prepare_build()
    ws.write_meta(make_meta(
        input_path=Path("a.apk"), input_sha256="a" * 64, input_size=1,
        input_type="apk", tool_versions={}, optional_scanners=("native_r2",),
    ))

    _merge_optional_scanners(ws, ("native_r2", "future"))

    meta = ws.read_meta()
    assert meta is not None
    assert meta.optional_scanners == ("native_r2", "future")
