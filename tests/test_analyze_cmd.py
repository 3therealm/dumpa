"""`dumpa analyze` command orchestration regressions and metadata helpers."""

from __future__ import annotations

import os
from pathlib import Path

from dumpa.commands import analyze as cmd
from dumpa.core.config import (
    AnalysisConfig,
    Config,
    const_env_native_r2_all_abis,
    const_env_play_lookup,
)
from dumpa.core.workspace import Workspace, make_meta


def test_merge_optional_scanners_persists_request(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    ws.prepare_build()
    ws.write_meta(make_meta(
        input_path=Path("a.apk"), input_sha256="a" * 64, input_size=1,
        input_type="apk", tool_versions={},
    ))

    cmd._merge_optional_scanners(ws, ("native_r2",))

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

    cmd._merge_optional_scanners(ws, ("native_r2", "future"))

    meta = ws.read_meta()
    assert meta is not None
    assert meta.optional_scanners == ("native_r2", "future")


def test_analyze_env_overrides_are_restored(tmp_path: Path, monkeypatch) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"not-a-real-apk")
    seen_env: list[tuple[str | None, str | None]] = []

    def fake_load_config() -> Config:
        seen_env.append((
            os.environ.get(const_env_play_lookup),
            os.environ.get(const_env_native_r2_all_abis),
        ))
        return Config(analysis=AnalysisConfig())

    monkeypatch.delenv(const_env_play_lookup, raising=False)
    monkeypatch.delenv(const_env_native_r2_all_abis, raising=False)
    monkeypatch.setattr(cmd, "load_config", fake_load_config)
    monkeypatch.setattr(cmd, "build_default_registry", lambda _paths: object())
    monkeypatch.setattr(cmd, "resolve_signing", lambda _signing, _config, _registry: None)
    monkeypatch.setattr(cmd, "sha256_file", lambda _path: "a" * 64)
    monkeypatch.setattr(cmd, "decide_reuse", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(cmd, "_maybe_autodump", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cmd, "_report_workspace", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cmd, "_maybe_xref", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cmd, "_maybe_decompile", lambda *_args, **_kwargs: None)

    cmd.analyze(apk, workspace=tmp_path / "ws", no_network=True, r2=True, all_abis=True)

    assert seen_env[0] == ("0", "1")
    assert const_env_play_lookup not in os.environ
    assert const_env_native_r2_all_abis not in os.environ
