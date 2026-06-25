"""dump-il2cpp workspace side effects."""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.commands.dump_il2cpp import _invalidate_report
from dumpa.core.errors import ToolExecutionError
from dumpa.core.tools import ResolvedTool, ToolSpec
from dumpa.core.workspace import Workspace
from dumpa.tools.il2cpp import Il2CppInputs
from dumpa.tools.il2cpp import dumper as dumper_mod
from dumpa.tools.il2cpp.dumper import Il2CppDumperEngine


def test_invalidate_report_removes_report_json(tmp_path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    report = ws.reports_dir / "report.json"
    report.parent.mkdir(parents=True)
    report.write_text("{}", encoding="UTF-8")
    # split sidecars must go too, else humans browsing reports/findings/ see stale data
    sidecar = ws.reports_dir / "findings" / "trackers.json"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text("{}", encoding="UTF-8")

    _invalidate_report(ws)

    assert not report.exists()
    assert not sidecar.exists()


def test_invalidate_report_missing_is_ok(tmp_path) -> None:
    _invalidate_report(Workspace(root=tmp_path / "ws"))


def _tool() -> ResolvedTool:
    return ResolvedTool(ToolSpec("il2cppdumper", ("fake-il2cpp-dumper",)), ("fake-il2cpp-dumper",), None)


def _inputs(tmp_path: Path) -> Il2CppInputs:
    binary = tmp_path / "libil2cpp.so"
    metadata = tmp_path / "global-metadata.dat"
    binary.write_bytes(b"\x7fELF")
    metadata.write_bytes(b"\xaf\x1b\xb1\xfa")
    return Il2CppInputs(binary=binary, metadata=metadata, arch="arm64-v8a")


def test_dumper_tolerates_interactive_exit_prompt_quietly(tmp_path: Path, monkeypatch) -> None:
    out = tmp_path / "out"
    seen: dict[str, object] = {}

    def fake_run(_cmd, **kwargs) -> None:
        seen.update(kwargs)
        (out / "dump.cs").write_text("// dumped\n", encoding="UTF-8")
        raise ToolExecutionError("interactive prompt")

    monkeypatch.setattr(dumper_mod, "run", fake_run)

    result = Il2CppDumperEngine().dump(_tool(), _inputs(tmp_path), out)

    assert seen["quiet"] is True
    assert "dump_cs" in result.artifacts


def test_dumper_still_fails_when_nonzero_produces_no_dump(tmp_path: Path, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(_cmd, **kwargs) -> None:
        seen.update(kwargs)
        raise ToolExecutionError("failed")

    monkeypatch.setattr(dumper_mod, "run", fake_run)

    with pytest.raises(ToolExecutionError):
        Il2CppDumperEngine().dump(_tool(), _inputs(tmp_path), tmp_path / "out")

    assert seen["quiet"] is True
