"""native_r2 scanner: entropy regions, function summary, ABI scoping — r2 mocked."""

from __future__ import annotations

import json
from pathlib import Path

from dumpa.core.errors import ToolNotFoundError
from dumpa.core.r2 import R2Analysis, R2Function, R2Section
from dumpa.core.workspace import Workspace
from dumpa.scanners import native_r2


class _Tool:
    version = "radare2 5.9.0"
    argv_prefix = ("/opt/r2/bin/radare2",)


class _Registry:
    """Fake ToolRegistry: resolves radare2 unless `absent`."""

    def __init__(self, *, absent: bool = False) -> None:
        self._absent = absent

    def resolve(self, name: str) -> _Tool:
        if self._absent:
            raise ToolNotFoundError("radare2 not found")
        return _Tool()


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


def _lib(ws: Workspace, abi: str, name: str = "libfoo.so") -> Path:
    p = ws.extracted_dir / "lib" / abi / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\x00" * 64)
    return p


def _section(name: str, entropy: float | None, perm: str = "-r-x") -> R2Section:
    return R2Section(name=name, vaddr=0x1000, paddr=0x400, size=2048,
                     perm=perm, entropy=entropy)


def _patch(monkeypatch, registry, analysis_for) -> None:
    monkeypatch.setattr(native_r2, "build_default_registry", lambda _paths: registry)
    monkeypatch.setattr(native_r2, "load_config", lambda: type("C", (), {"tool_paths": {}})())
    monkeypatch.setattr(native_r2.r2, "analyze", analysis_for)


def _one(funcs=None, sections=None) -> R2Analysis:
    return R2Analysis(version="radare2 5.9.0",
                      functions=funcs or [R2Function("sym.f", 0x1100, 32, 2)],
                      sections=sections or [])


# --- entropy classification --------------------------------------------------

def test_packed_section_high_confidence(tmp_path: Path, monkeypatch) -> None:
    ws = _ws(tmp_path)
    _lib(ws, "arm64-v8a")
    _patch(monkeypatch, _Registry(),
           lambda _p, argv_prefix=("radare2",), version=None: _one(sections=[_section(".text", 7.91)]))

    findings = native_r2.scan(ws)
    regions = [f for f in findings if f.kind == native_r2.const_native_region_kind]
    assert len(regions) == 1
    r = regions[0]
    assert r.attributes["classification"] == "packed"
    assert r.confidence.value == "high"
    loc = r.locations[0]
    assert loc.file_offset == 0x400 and loc.rva == 0x1000


def test_elevated_section_medium(tmp_path: Path, monkeypatch) -> None:
    ws = _ws(tmp_path)
    _lib(ws, "arm64-v8a")
    _patch(monkeypatch, _Registry(),
           lambda _p, argv_prefix=("radare2",), version=None: _one(sections=[_section(".rodata", 6.7)]))

    regions = [f for f in native_r2.scan(ws) if f.kind == native_r2.const_native_region_kind]
    assert len(regions) == 1
    assert regions[0].attributes["classification"] == "high-entropy"
    assert regions[0].confidence.value == "medium"


def test_low_entropy_not_flagged(tmp_path: Path, monkeypatch) -> None:
    ws = _ws(tmp_path)
    _lib(ws, "arm64-v8a")
    _patch(monkeypatch, _Registry(),
           lambda _p, argv_prefix=("radare2",), version=None: _one(sections=[_section(".text", 5.0)]))

    findings = native_r2.scan(ws)
    assert not [f for f in findings if f.kind == native_r2.const_native_region_kind]
    # summary still emitted
    assert [f for f in findings if f.kind == native_r2.const_native_function_summary_kind]


def test_self_modifying_section(tmp_path: Path, monkeypatch) -> None:
    ws = _ws(tmp_path)
    _lib(ws, "arm64-v8a")
    _patch(monkeypatch, _Registry(),
           lambda _p, argv_prefix=("radare2",), version=None: _one(
               sections=[_section(".text", 5.0, perm="-rwx")]))

    regions = [f for f in native_r2.scan(ws) if f.kind == native_r2.const_native_region_kind]
    assert [r for r in regions if r.attributes["classification"] == "self-modifying"]


# --- summary + sidecar -------------------------------------------------------

def test_summary_and_sidecar(tmp_path: Path, monkeypatch) -> None:
    ws = _ws(tmp_path)
    _lib(ws, "arm64-v8a")
    big = R2Function("sym.huge", 0x2000, native_r2._OVERSIZED_FN_BYTES + 1, 50)
    _patch(monkeypatch, _Registry(),
           lambda _p, argv_prefix=("radare2",), version=None: _one(
               funcs=[R2Function("sym.f", 0x1100, 16, 1), big],
               sections=[_section(".text", 7.91)]))

    findings = native_r2.scan(ws)
    summary = [f for f in findings if f.kind == native_r2.const_native_function_summary_kind]
    assert len(summary) == 1
    assert summary[0].attributes["function_count"] == "2"
    assert summary[0].attributes["stored_function_count"] == "2"
    assert summary[0].attributes["oversized_count"] == "1"

    sidecar = ws.native_r2_dir / "arm64-v8a__libfoo.so.json"
    assert sidecar.is_file()
    data = json.loads(sidecar.read_text())
    assert data["r2_version"] == "radare2 5.9.0"
    assert data["function_count"] == 2
    assert data["stored_function_count"] == 2
    assert data["functions_truncated"] is False
    assert data["functions"] and data["regions"]


def test_sidecar_records_truncated_function_inventory(tmp_path: Path, monkeypatch) -> None:
    ws = _ws(tmp_path)
    _lib(ws, "arm64-v8a")
    analysis = R2Analysis(
        version="radare2 5.9.0",
        functions=[R2Function("sym.a", 0x1100, 16, 1)],
        sections=[],
        total_function_count=2,
        functions_truncated=True,
    )
    _patch(monkeypatch, _Registry(),
           lambda _p, argv_prefix=("radare2",), version=None: analysis)

    findings = native_r2.scan(ws)
    summary = next(f for f in findings if f.kind == native_r2.const_native_function_summary_kind)
    assert summary.attributes["function_count"] == "2"
    assert summary.attributes["stored_function_count"] == "1"
    assert summary.attributes["functions_truncated"] == "true"

    sidecar = ws.native_r2_dir / "arm64-v8a__libfoo.so.json"
    data = json.loads(sidecar.read_text())
    assert data["function_count"] == 2
    assert data["stored_function_count"] == 1
    assert data["functions_truncated"] is True


# --- fail-soft + ABI scoping -------------------------------------------------

def test_radare2_absent_returns_empty(tmp_path: Path, monkeypatch) -> None:
    ws = _ws(tmp_path)
    _lib(ws, "arm64-v8a")
    _patch(monkeypatch, _Registry(absent=True), lambda _p, argv_prefix=("radare2",), version=None: _one())
    assert native_r2.scan(ws) == []


def test_analysis_none_skips_lib(tmp_path: Path, monkeypatch) -> None:
    ws = _ws(tmp_path)
    _lib(ws, "arm64-v8a")
    _patch(monkeypatch, _Registry(), lambda _p, argv_prefix=("radare2",), version=None: None)
    assert native_r2.scan(ws) == []


def test_only_primary_abi_analyzed(tmp_path: Path, monkeypatch) -> None:
    ws = _ws(tmp_path)
    _lib(ws, "x86")
    _lib(ws, "arm64-v8a")
    seen: list[str] = []

    def fake(path: Path, argv_prefix=("radare2",), version=None) -> R2Analysis:
        seen.append(path.parent.name)
        assert argv_prefix == _Tool.argv_prefix
        return _one(sections=[_section(".text", 7.91)])

    _patch(monkeypatch, _Registry(), fake)
    native_r2.scan(ws)
    assert seen == ["arm64-v8a"]            # x86 skipped (preference picks arm64)


def test_no_libs_returns_empty(tmp_path: Path, monkeypatch) -> None:
    ws = _ws(tmp_path)
    _patch(monkeypatch, _Registry(), lambda _p, argv_prefix=("radare2",), version=None: _one())
    assert native_r2.scan(ws) == []
