"""Native scanner: per-ABI metadata for every lib/<abi>/*.so.

Reads each shared object's ELF header (no external tool) for a quick ABI/bitness/machine
finding, then parses the full ELF (sections, symbols, PT_LOAD segments) to emit a
per-library `native-symbol` finding. The full section/export/import lists are written to
a sidecar under `dumps/native/` so the report stays compact (counts only); RVAs for
offset-located findings are backfilled separately in `scanners.enrich_native_rvas`.

It also emits a per-library grouped printable-string dump (a `native-strings` finding +
a sidecar under `dumps/native-strings/`), streamed so a hundreds-of-MB `.so` is never
loaded whole. Suspicious-region mapping and radare2-backed scanning remain future work.
"""

from __future__ import annotations

import json
import logging
import re
import struct
from pathlib import Path

from dumpa.core.elf import ElfFile, parse_elf
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_native_kind = "native"
const_native_symbol_kind = "native-symbol"
const_native_strings_kind = "native-strings"
_ELF_MAGIC = b"\x7fELF"

# Printable-string extraction (streamed, like the endpoint scanner).
_STR_MIN_LEN = 5
_STR_CHUNK = 1 << 20
_STR_OVERLAP = 1024                  # >= longest run we want intact across a chunk edge
_STR_MAX_FILE_BYTES = 512 << 20
_STR_MAX_COUNT = 50_000              # unique strings kept per library
# A "string" = a run of printable ASCII (0x20-0x7e) or tab, >= _STR_MIN_LEN bytes.
_STR_RE = re.compile(rb"[\x20-\x7e\x09]{%d,}" % _STR_MIN_LEN)
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


def _extract_strings(path: Path) -> tuple[list[tuple[int, str]], bool]:
    """Stream printable-ASCII runs (>= _STR_MIN_LEN) from a binary, deduped by text.

    Returns (sorted [(first_offset, text)], truncated). Reads in bounded chunks with
    overlap so a run spanning a chunk edge isn't split (deferred and re-caught in the
    next window), mirroring the endpoint scanner's streaming idiom.
    """
    seen: dict[str, int] = {}
    truncated = False

    def record(raw: bytes, offset: int) -> None:
        nonlocal truncated
        text = raw.decode("latin-1")
        if text in seen:
            return
        if len(seen) >= _STR_MAX_COUNT:
            truncated = True
            return
        seen[text] = offset

    with path.open("rb") as f:
        tail = b""
        base = 0
        while True:
            chunk = f.read(_STR_CHUNK)
            if not chunk:
                break
            window = tail + chunk
            window_start = base - len(tail)
            for m in _STR_RE.finditer(window):
                if m.end() == len(window):
                    continue          # may continue into the next chunk; re-caught there
                record(m.group(), window_start + m.start())
            base += len(chunk)
            tail = window[-_STR_OVERLAP:]
        if tail:
            window_start = base - len(tail)
            for m in _STR_RE.finditer(tail):
                record(m.group(), window_start + m.start())
    return sorted((off, txt) for txt, off in seen.items()), truncated


def _write_strings_sidecar(ws: Workspace, abi: str, so: Path, elf: ElfFile,
                           strings: list[tuple[int, str]], truncated: bool) -> str | None:
    """Write the grouped string dump to dumps/native-strings/; return its rel path."""
    sidecar = ws.native_strings_dir / f"{abi}__{so.name}.strings.json"
    payload = {
        "abi": abi, "lib": so.name, "machine": elf.machine, "bitness": elf.bitness,
        "count": len(strings), "truncated": truncated,
        "strings": [{"offset": off, "text": txt} for off, txt in strings],
    }
    try:
        ws.native_strings_dir.mkdir(parents=True, exist_ok=True)
        with sidecar.open("w", encoding="UTF-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError:
        logger.warning("could not write native strings sidecar for %s", so, exc_info=True)
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
        if so.stat().st_size <= _STR_MAX_FILE_BYTES:
            strings, truncated = _extract_strings(so)
            str_attrs = {"abi": abi, "string_count": str(len(strings))}
            str_sidecar = _write_strings_sidecar(ws, abi, so, elf, strings, truncated)
            if str_sidecar is not None:
                str_attrs["sidecar"] = str_sidecar
            findings.append(Finding(
                kind=const_native_strings_kind,
                subject=f"{abi}/{so.name}",
                confidence=Confidence.HIGH,
                state=FindingState.PRESENT,
                attributes=str_attrs,
                evidence=[Evidence(
                    description=f"{len(strings)} printable strings (>= {_STR_MIN_LEN} chars)",
                    snippet=rel, tool="native-strings")],
                locations=[Location(file_path=rel)],
            ))
    return findings
