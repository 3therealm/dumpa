"""Native ELF metadata scanner + protections bundle/scanner."""

from __future__ import annotations

import struct
from pathlib import Path

from dumpa.core.report import Confidence
from dumpa.core.rules import load_builtin
from dumpa.core.workspace import Workspace
from dumpa.scanners import native as native_scanner
from dumpa.scanners import protection as protection_scanner


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


def _elf(machine: int, ei_class: int = 2) -> bytes:
    # e_ident(16) + e_type(2) + e_machine(2), little-endian
    ident = b"\x7fELF" + bytes([ei_class, 1]) + b"\x00" * 10
    return ident + struct.pack("<H", 2) + struct.pack("<H", machine) + b"\x00" * 20


# --- native ------------------------------------------------------------------

def test_native_reports_arch(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "lib" / "arm64-v8a").mkdir(parents=True)
    (ws.extracted_dir / "lib" / "arm64-v8a" / "libfoo.so").write_bytes(_elf(0xB7))
    findings = native_scanner.scan(ws)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "native"
    assert f.subject == "arm64-v8a/libfoo.so"
    assert f.attributes["machine"] == "AArch64"
    assert f.attributes["bitness"] == "64-bit"
    assert f.attributes["abi"] == "arm64-v8a"


def test_native_skips_non_elf(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "lib" / "x86").mkdir(parents=True)
    (ws.extracted_dir / "lib" / "x86" / "libbad.so").write_bytes(b"not an elf at all")
    assert native_scanner.scan(ws) == []


# --- protections -------------------------------------------------------------

def test_protections_bundle_loads() -> None:
    bundle = load_builtin("protections")
    assert bundle.name == "protections"
    assert len(bundle.rules) >= 10


def test_protection_detects_packer_by_libname(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "lib" / "arm64-v8a").mkdir(parents=True)
    (ws.extracted_dir / "lib" / "arm64-v8a" / "libjiagu.so").write_bytes(b"\x7fELF")
    findings = protection_scanner.scan(ws)
    jiagu = next((f for f in findings if "Jiagu" in f.subject), None)
    assert jiagu is not None
    assert jiagu.kind == "protection"
    assert jiagu.attributes["category"] == "packer"
    assert jiagu.confidence is Confidence.HIGH


def test_protection_detects_tracerpid_marker(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "classes.dex").write_bytes(b"reads /proc/self/status TracerPid: 0")
    findings = protection_scanner.scan(ws)
    assert any(f.attributes.get("category") == "anti-debug" for f in findings)


def test_protection_clean(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "classes.dex").write_bytes(b"perfectly ordinary bytecode")
    assert protection_scanner.scan(ws) == []
