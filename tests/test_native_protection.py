"""Native ELF metadata scanner + protections bundle/scanner."""

from __future__ import annotations

import struct
from pathlib import Path

from _elf_build import LOAD_VADDR_BASE, build_elf

from dumpa.core.report import Confidence, Finding, Location
from dumpa.core.rules import apply_bundle, load_builtin, load_bundle
from dumpa.core.workspace import Workspace
from dumpa.scanners import enrich_native_rvas
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


def test_native_symbol_finding_and_sidecar(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "lib" / "arm64-v8a").mkdir(parents=True)
    data, _ = build_elf(exports=(("foo", 0x10500, 8), ("bar", 0x10600, 8)),
                        imports=("malloc",))
    (ws.extracted_dir / "lib" / "arm64-v8a" / "liby.so").write_bytes(data)
    findings = native_scanner.scan(ws)
    sym = [f for f in findings if f.kind == "native-symbol"]
    assert len(sym) == 1
    assert sym[0].attributes["export_count"] == "2"
    assert sym[0].attributes["import_count"] == "1"
    sidecar = ws.root / sym[0].attributes["sidecar"]
    assert sidecar.is_file()


def test_enrich_backfills_native_rva(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "lib" / "arm64-v8a").mkdir(parents=True)
    data, payload_off = build_elf(payload=b"SECRET_MARKER")
    (ws.extracted_dir / "lib" / "arm64-v8a" / "libz.so").write_bytes(data)
    rel = "lib/arm64-v8a/libz.so"
    finding = Finding(kind="protection", subject="marker", confidence=Confidence.HIGH,
                      locations=[Location(file_path=rel, file_offset=payload_off)])
    out = enrich_native_rvas([finding], ws)
    assert out[0].locations[0].rva == LOAD_VADDR_BASE + payload_off


def test_enrich_leaves_non_lib_findings(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    finding = Finding(kind="secret", subject="key", confidence=Confidence.HIGH,
                      locations=[Location(file_path="classes.dex", file_offset=42)])
    out = enrich_native_rvas([finding], ws)
    assert out[0].locations[0].rva is None
    assert out[0] is finding


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


def test_hex_rule_matches_native_lib_and_backfills_rva(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "lib" / "arm64-v8a").mkdir(parents=True)
    data, payload_off = build_elf(payload=b"\xde\xad\xbe\xef\x11\x22")
    (ws.extracted_dir / "lib" / "arm64-v8a" / "libp.so").write_bytes(data)
    text = ('[bundle]\nname="t"\nversion="1"\nupdated="d"\n\n'
            '[[rule]]\nkind="protection"\nsubject="Example stub"\nconfidence="high"\n'
            'category="packer"\nhex=["DE AD BE EF"]\ntargets=["lib/**/*.so"]\n')
    (tmp_path / "b.toml").write_text(text)
    bundle = load_bundle(tmp_path / "b.toml")
    findings = apply_bundle(bundle, ws.extracted_dir)
    assert len(findings) == 1
    assert findings[0].locations[0].file_offset == payload_off
    out = enrich_native_rvas(findings, ws)
    assert out[0].locations[0].rva == LOAD_VADDR_BASE + payload_off
