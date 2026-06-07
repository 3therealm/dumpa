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

from dumpa.core import cache
from dumpa.core.elf import ElfFile, parse_elf
from dumpa.core.report import Confidence, Finding
from dumpa.core.rules import load_builtin
from dumpa.core.workspace import Workspace, WorkspaceMeta
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


@dataclasses.dataclass(frozen=True)
class ScannerSpec:
    """A scanner plus the rule bundles whose versions gate its cached output."""
    name: str                       # cache id, e.g. "tracker"
    fn: Scanner
    bundles: tuple[str, ...] = ()    # builtin bundle names the scanner consumes


# Registration order is the run order; engine detection first so its findings exist
# for primary_engine() and so detail scanners (unity) follow their parent engine.
SCANNERS: tuple[ScannerSpec, ...] = (
    ScannerSpec("engine", engine.scan, ("engines",)),
    ScannerSpec("manifest_privacy", manifest_privacy.scan, ("manifest",)),
    ScannerSpec("tracker", tracker.scan, ("trackers",)),
    ScannerSpec("privacy", privacy.scan, ("privacy",)),
    ScannerSpec("protection", protection.scan, ("protections",)),
    ScannerSpec("secret", secret.scan, ("secrets",)),
    ScannerSpec("native", native.scan),
    ScannerSpec("endpoint", endpoint.scan),
)
# Unity deep helper runs only when the engine scanner flagged Unity.
UNITY_SPEC = ScannerSpec("unity", unity.scan)

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


def _run_spec(ws: Workspace, spec: ScannerSpec, meta: WorkspaceMeta | None) -> list[Finding]:
    """Run one scanner, serving from / writing to the content-hash cache when possible.

    Caching is active only for a marked workspace (meta present); without it there is no
    input hash to key on, so the scanner just runs (the case for in-memory unit tests).
    """
    if meta is None:
        return list(spec.fn(ws))
    key = cache.compute_scanner_key(
        meta.input_sha256, {b: load_builtin(b).version for b in spec.bundles}
    )
    cached = cache.read_scanner_cache(ws, spec.name, key)
    if cached is not None:
        return cached
    produced = list(spec.fn(ws))
    cache.write_scanner_cache(ws, spec.name, key, produced)
    return produced


def run_all(ws: Workspace, *, use_cache: bool = True) -> list[Finding]:
    """Run every registered scanner over the workspace and concatenate their findings.

    Per-scanner findings are memoized under a content-hash key (input + dumpa + rule-bundle
    versions); pass use_cache=False to force a fresh scan. `enrich_native_rvas` runs on the
    assembled list every time — it is a cheap deterministic post-pass, so it stays uncached.
    """
    meta = ws.read_meta() if use_cache else None
    findings: list[Finding] = []
    for spec in SCANNERS:
        findings.extend(_run_spec(ws, spec, meta))
    if any(f.kind == "engine" and f.subject == "Unity" for f in findings):
        findings.extend(_run_spec(ws, UNITY_SPEC, meta))
    return enrich_native_rvas(findings, ws)


def primary_engine(findings: list[Finding]) -> str | None:
    """Pick the most likely engine: highest-confidence 'engine' finding (bundle order breaks ties)."""
    engines = [f for f in findings if f.kind == "engine"]
    if not engines:
        return None
    return max(engines, key=lambda f: _CONFIDENCE_RANK[f.confidence]).subject
