"""Engine + Unity scanners and primary_engine selection."""

from __future__ import annotations

import struct
from pathlib import Path

from dumpa.core.report import Confidence, Finding
from dumpa.core.workspace import Workspace
from dumpa.scanners import engine as engine_scanner
from dumpa.scanners import primary_engine, run_all
from dumpa.scanners import unity as unity_scanner

_META_MAGIC = 0xFAB11BAF


def _touch(root: Path, rel: str, data: bytes = b"\x00") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _metadata_blob(version: int) -> bytes:
    return struct.pack("<Ii", _META_MAGIC, version) + b"\x00" * 16


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


# --- engine scanner ----------------------------------------------------------

def test_engine_scan_detects_unity(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")
    findings = engine_scanner.scan(ws)
    assert any(f.kind == "engine" and f.subject == "Unity" for f in findings)


def test_engine_scan_no_extracted_dir(tmp_path: Path) -> None:
    assert engine_scanner.scan(Workspace(root=tmp_path / "missing")) == []


# --- unity scanner -----------------------------------------------------------

def test_unity_il2cpp_backend_and_metadata(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")
    _touch(ws.extracted_dir, "assets/bin/Data/Managed/Metadata/global-metadata.dat",
           _metadata_blob(29))
    subjects = {f.subject for f in unity_scanner.scan(ws)}
    assert "Unity scripting backend: IL2CPP" in subjects
    assert "IL2CPP metadata version 29" in subjects


def test_unity_mono_backend(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libmonobdwgc-2.0.so")
    subjects = {f.subject for f in unity_scanner.scan(ws)}
    assert "Unity scripting backend: Mono" in subjects


def test_unity_bad_metadata_magic(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")
    _touch(ws.extracted_dir, "assets/bin/Data/Managed/Metadata/global-metadata.dat",
           b"NOTMAGIC" + b"\x00" * 8)
    subjects = {f.subject for f in unity_scanner.scan(ws)}
    assert "global-metadata.dat: unrecognized header" in subjects


def test_unity_noop_on_non_unity(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libflutter.so")
    assert unity_scanner.scan(ws) == []


# --- aggregation + primary engine -------------------------------------------

def test_run_all_aggregates(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")
    kinds = {f.kind for f in run_all(ws)}
    assert "engine" in kinds
    assert "engine-detail" in kinds


def test_primary_engine_prefers_high_confidence() -> None:
    findings = [
        Finding(kind="engine", subject="Defold", confidence=Confidence.MEDIUM),
        Finding(kind="engine", subject="Unity", confidence=Confidence.HIGH),
    ]
    assert primary_engine(findings) == "Unity"


def test_primary_engine_none_when_no_engine() -> None:
    assert primary_engine([Finding(kind="tracker", subject="x", confidence=Confidence.LOW)]) is None
