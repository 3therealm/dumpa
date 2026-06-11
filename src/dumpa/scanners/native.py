"""Native scanner: per-ABI metadata for every lib/<abi>/*.so.

Reads each shared object's ELF header (no external tool) for a quick ABI/bitness/machine
finding, then parses the full ELF (sections, symbols, PT_LOAD segments) to emit a
per-library `native-symbol` finding. The full section/export/import lists are written to
a sidecar under `dumps/native/` so the report stays compact (counts only); RVAs for
offset-located findings are backfilled separately in `scanners.enrich_native_rvas`.
Suspicious-region mapping and radare2-backed scanning remain future work.
"""

from __future__ import annotations

import json
import logging
import struct
from pathlib import Path

from dumpa.core.elf import ElfFile, parse_elf
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_native_kind = "native"
const_native_symbol_kind = "native-symbol"
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


def _write_sidecar(ws: Workspace, abi: str, so: Path, elf: ElfFile) -> str | None:
    """Write the full section/export/import lists to dumps/native/; return its rel path."""
    sidecar = ws.native_dir / f"{abi}__{so.name}.json"
    payload = {
        "abi": abi, "lib": so.name, "machine": elf.machine, "bitness": elf.bitness,
        "sections": [{"name": s.name, "type": s.type, "addr": s.addr,
                      "offset": s.offset, "size": s.size, "flags": s.flags}
                     for s in elf.sections],
        "exports": [{"name": s.name, "rva": s.value, "size": s.size} for s in elf.exports],
        "imports": [{"name": s.name} for s in elf.imports],
    }
    try:
        ws.native_dir.mkdir(parents=True, exist_ok=True)
        with sidecar.open("w", encoding="UTF-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError:
        logger.warning("could not write native sidecar for %s", so, exc_info=True)
        return None
    return sidecar.relative_to(ws.root).as_posix()


def scan(ws: Workspace) -> list[Finding]:
    """Report ELF metadata + a symbol/section inventory for each lib/<abi>/*.so."""
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
        elf = parse_elf(so)
        if elf is None:
            continue
        attributes = {"abi": abi, "export_count": str(len(elf.exports)),
                      "import_count": str(len(elf.imports)),
                      "section_count": str(len(elf.sections))}
        sidecar_rel = _write_sidecar(ws, abi, so, elf)
        if sidecar_rel is not None:
            attributes["sidecar"] = sidecar_rel
        findings.append(Finding(
            kind=const_native_symbol_kind,
            subject=f"{abi}/{so.name}",
            confidence=Confidence.HIGH,
            state=FindingState.PRESENT,
            attributes=attributes,
            evidence=[Evidence(
                description=(f"{len(elf.exports)} exports, {len(elf.imports)} imports, "
                             f"{len(elf.sections)} sections"),
                snippet=rel, tool="elf")],
            locations=[Location(file_path=rel)],
        ))
    return findings
