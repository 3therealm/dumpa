"""Native scanner: per-ABI metadata for every lib/<abi>/*.so.

Reads each shared object's ELF header (no external tool) and reports its ABI, bitness,
and machine. Deeper native analysis — symbols, imports/exports, sections, RVAs,
suspicious regions, radare2-backed region scanning — is future work; the protections
scanner already covers native protection signatures by filename/markers.
"""

from __future__ import annotations

import struct
from pathlib import Path

from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace

const_native_kind = "native"
_ELF_MAGIC = b"\x7fELF"
# e_machine -> readable architecture.
_MACHINES = {
    0x28: "ARM (32-bit)",
    0xB7: "AArch64",
    0x03: "x86",
    0x3E: "x86-64",
    0xF3: "RISC-V",
}


def _read_elf(path: Path) -> tuple[str, str] | None:
    """Return (bitness, machine) from an ELF header, or None if not a valid ELF."""
    try:
        with path.open("rb") as f:
            head = f.read(20)
    except OSError:
        return None
    if len(head) < 20 or head[:4] != _ELF_MAGIC:
        return None
    ei_class = head[4]          # 1 = 32-bit, 2 = 64-bit
    ei_data = head[5]           # 1 = little-endian, 2 = big-endian
    bitness = {1: "32-bit", 2: "64-bit"}.get(ei_class, "unknown")
    endian = "<" if ei_data == 1 else ">"
    (e_machine,) = struct.unpack(f"{endian}H", head[18:20])
    machine = _MACHINES.get(e_machine, f"machine 0x{e_machine:x}")
    return (bitness, machine)


def scan(ws: Workspace) -> list[Finding]:
    """Report ELF metadata for each native library under lib/<abi>/."""
    ex = ws.extracted_dir
    if not ex.is_dir():
        return []
    findings: list[Finding] = []
    for so in sorted(ex.glob("lib/*/*.so")):
        info = _read_elf(so)
        if info is None:
            continue
        bitness, machine = info
        rel = so.relative_to(ex).as_posix()
        abi = so.parent.name
        findings.append(Finding(
            kind=const_native_kind,
            subject=f"{abi}/{so.name}",
            confidence=Confidence.HIGH,
            state=FindingState.PRESENT,
            attributes={"abi": abi, "bitness": bitness, "machine": machine,
                        "size": str(so.stat().st_size)},
            evidence=[Evidence(description=f"ELF {bitness} {machine}", snippet=rel, tool="native")],
            locations=[Location(file_path=rel)],
        ))
    return findings
