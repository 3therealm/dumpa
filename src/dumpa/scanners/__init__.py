"""Scanners: pure `(workspace) -> list[Finding]` functions aggregated into a report.

Every scanner reads a populated workspace's `extracted/` tree and returns Findings
in the shared `core.report` model. `reporting.build_report` runs them all, so adding
a capability (trackers, protections, native, ...) is "register a scanner", never
"add a subsystem". Phase 4 ships engine detection + the Unity deep helper.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from pathlib import PurePosixPath

from dumpa.core.elf import ElfFile, parse_elf
from dumpa.core.report import Confidence, Finding
from dumpa.core.workspace import Workspace
from dumpa.scanners import (
    endpoint,
    engine,
    manifest_privacy,
    native,
    privacy,
    protection,
    secret,
    tracker,
    unity,
)

Scanner = Callable[[Workspace], list[Finding]]

# Registration order is the run order; engine detection first so its findings exist
# for primary_engine() and so detail scanners (unity) follow their parent engine.
SCANNERS: tuple[Scanner, ...] = (
    engine.scan, manifest_privacy.scan, tracker.scan, privacy.scan, protection.scan,
    secret.scan, native.scan, endpoint.scan,
)

_CONFIDENCE_RANK = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}


def _is_lib_so(rel: str) -> bool:
    """True for an extracted lib/<abi>/<name>.so path."""
    parts = PurePosixPath(rel).parts
    return len(parts) == 3 and parts[0] == "lib" and parts[2].endswith(".so")


def enrich_native_rvas(findings: list[Finding], ws: Workspace) -> list[Finding]:
    """Backfill Location.rva on any finding located by file offset inside a lib/*.so.

    Cross-cutting pass: protection/tracker/secret findings carry a file offset but no
    RVA; map each through the covering PT_LOAD segment. Each library is parsed once.
    """
    cache: dict[str, ElfFile | None] = {}

    def mapper(rel: str) -> ElfFile | None:
        if rel not in cache:
            path = ws.extracted_dir / rel
            cache[rel] = parse_elf(path) if path.is_file() else None
        return cache[rel]

    out: list[Finding] = []
    for finding in findings:
        new_locs: list | None = None
        for i, loc in enumerate(finding.locations):
            if (loc.rva is not None or loc.file_offset is None
                    or not loc.file_path or not _is_lib_so(loc.file_path)):
                continue
            elf = mapper(loc.file_path)
            if elf is None:
                continue
            rva = elf.offset_to_rva(loc.file_offset)
            if rva is None:
                continue
            if new_locs is None:
                new_locs = list(finding.locations)
            new_locs[i] = dataclasses.replace(loc, rva=rva)
        out.append(dataclasses.replace(finding, locations=new_locs)
                   if new_locs is not None else finding)
    return out


def run_all(ws: Workspace) -> list[Finding]:
    """Run every registered scanner over the workspace and concatenate their findings."""
    findings: list[Finding] = []
    for scan in SCANNERS:
        findings.extend(scan(ws))
    if any(f.kind == "engine" and f.subject == "Unity" for f in findings):
        findings.extend(unity.scan(ws))
    return enrich_native_rvas(findings, ws)


def primary_engine(findings: list[Finding]) -> str | None:
    """Pick the most likely engine: highest-confidence 'engine' finding (bundle order breaks ties)."""
    engines = [f for f in findings if f.kind == "engine"]
    if not engines:
        return None
    return max(engines, key=lambda f: _CONFIDENCE_RANK[f.confidence]).subject
