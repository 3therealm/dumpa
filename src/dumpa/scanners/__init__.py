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
from dumpa.core.dex import DexFile, parse_dex
from dumpa.core.domains import DomainOwner, build_domain_table
from dumpa.core.elf import ElfFile, parse_elf
from dumpa.core.report import Confidence, Evidence, Finding, Location
from dumpa.core.rules import load_builtin
from dumpa.core.workspace import Workspace, WorkspaceMeta
from dumpa.scanners import (
    dex,
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
    ScannerSpec("dex", dex.scan),
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


def enrich_dex_locations(findings: list[Finding], ws: Workspace) -> list[Finding]:
    """Backfill Location.dex_class/.dex_method on any finding located by offset in a .dex.

    Twin of enrich_native_rvas: a content scanner records (file_path=<dex>, file_offset);
    map each offset through the parsed dex to its owning class (and method, when the offset
    lands in bytecode). Each dex is parsed once. Findings already carrying a dex_class, or
    whose offset resolves to nothing structurally (e.g. a plain string constant), pass
    through unchanged.
    """
    cache: dict[str, DexFile | None] = {}

    def mapper(rel: str) -> DexFile | None:
        if rel not in cache:
            path = ws.extracted_dir / rel
            cache[rel] = parse_dex(path) if path.is_file() else None
        return cache[rel]

    out: list[Finding] = []
    for finding in findings:
        new_locs: list | None = None
        for i, loc in enumerate(finding.locations):
            if (loc.dex_class is not None or loc.file_offset is None
                    or not loc.file_path or not loc.file_path.endswith(".dex")):
                continue
            dex_file = mapper(loc.file_path)
            if dex_file is None:
                continue
            hit = dex_file.locate(loc.file_offset)
            if hit is None:
                continue
            dex_class, dex_method = hit
            if new_locs is None:
                new_locs = list(finding.locations)
            new_locs[i] = dataclasses.replace(loc, dex_class=dex_class, dex_method=dex_method)
        out.append(dataclasses.replace(finding, locations=new_locs)
                   if new_locs is not None else finding)
    return out


const_attribution_tool = "domain-attribution"


def _attribution_evidence(owner: DomainOwner) -> Evidence:
    """A stable Evidence (same description across runs) so re-attribution de-dupes."""
    return Evidence(
        description=(f"host owned by {owner.owner} "
                     f"(via {owner.source} v{owner.version})"),
        tool=const_attribution_tool,
    )


def _has_equivalent_evidence(evidence: list[Evidence], candidate: Evidence) -> bool:
    return any(e.description == candidate.description and e.tool == candidate.tool
              for e in evidence)


def enrich_domain_attribution(findings: list[Finding], ws: Workspace) -> list[Finding]:
    """Attribute observed hosts to owning SDK/company using the DomainTable. Idempotent.

    Stamps ownership onto existing findings without synthesizing new ones or touching
    confidence:
    - endpoint findings gain `owner`/`category` attributes + a linking Evidence,
    - tracker findings gain a `Location(domain=host)` + a linking Evidence, attached to the
      tracker chosen by DomainOwner.subject match, else by owner-only fallback ONLY when
      exactly one tracker exists for that owner (never cross-attributes within Google/Meta/...).

    Every addition is guarded (attribute key absent / no existing Location with that domain /
    no equivalent Evidence), so re-running on an already-enriched report is a no-op — relied on
    by the domain-aware export path. `ws` is unused (the table is built from in-repo bundles),
    kept for signature parity with the sibling enrich passes.
    """
    table = build_domain_table()
    if len(table) == 0:
        return findings

    # One de-duped observed-host set: endpoint subjects UNION every Location.domain.
    observed: set[str] = set()
    for finding in findings:
        if finding.kind == "endpoint":
            observed.add(finding.subject.lower())
        for loc in finding.locations:
            if loc.domain:
                observed.add(loc.domain.lower())

    resolved: dict[str, DomainOwner] = {
        host: owner for host in observed if (owner := table.resolve(host)) is not None
    }
    if not resolved:
        return findings

    # Index trackers for the linking step (subject -> indices, owner -> indices).
    by_subject: dict[str, list[int]] = {}
    by_owner: dict[str, list[int]] = {}
    for i, f in enumerate(findings):
        if f.kind != "tracker":
            continue
        by_subject.setdefault(f.subject, []).append(i)
        owner_attr = f.attributes.get("owner")
        if owner_attr:
            by_owner.setdefault(owner_attr, []).append(i)

    # Accumulate per-index edits, then materialize with dataclasses.replace once each.
    new_attrs: dict[int, dict[str, str]] = {}
    new_locs: dict[int, list[Location]] = {}
    new_evidence: dict[int, list[Evidence]] = {}

    def _attrs(i: int) -> dict[str, str]:
        return new_attrs.setdefault(i, dict(findings[i].attributes))

    def _locs(i: int) -> list[Location]:
        return new_locs.setdefault(i, list(findings[i].locations))

    def _evidence(i: int) -> list[Evidence]:
        return new_evidence.setdefault(i, list(findings[i].evidence))

    # Step 3: endpoint findings gain owner/category + linking Evidence.
    for i, f in enumerate(findings):
        if f.kind != "endpoint":
            continue
        owner = resolved.get(f.subject.lower())
        if owner is None:
            continue
        attrs = _attrs(i)
        if "owner" not in attrs:
            attrs["owner"] = owner.owner
        if "category" not in attrs:
            attrs["category"] = owner.category
        ev = _attribution_evidence(owner)
        if not _has_equivalent_evidence(_evidence(i), ev):
            _evidence(i).append(ev)

    # Step 4: attach Location(domain=host) to the chosen tracker per resolved host.
    # Sorted for deterministic Location order when one tracker owns several hosts.
    for host, owner in sorted(resolved.items()):
        target: int | None = None
        if owner.subject is not None and by_subject.get(owner.subject):
            target = by_subject[owner.subject][0]
        else:
            owners_idx = by_owner.get(owner.owner, [])
            if len(owners_idx) == 1:
                target = owners_idx[0]
        if target is None:
            continue
        if any(loc.domain == host for loc in _locs(target)):
            continue
        _locs(target).append(Location(domain=host))
        ev = _attribution_evidence(owner)
        if not _has_equivalent_evidence(_evidence(target), ev):
            _evidence(target).append(ev)

    touched = set(new_attrs) | set(new_locs) | set(new_evidence)
    if not touched:
        return findings
    out: list[Finding] = []
    for i, f in enumerate(findings):
        if i not in touched:
            out.append(f)
            continue
        out.append(dataclasses.replace(
            f,
            attributes=new_attrs.get(i, f.attributes),
            locations=new_locs.get(i, f.locations),
            evidence=new_evidence.get(i, f.evidence),
        ))
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
    versions); pass use_cache=False to force a fresh scan. `enrich_native_rvas`,
    `enrich_dex_locations`, and `enrich_domain_attribution` run on the assembled list every
    time — cheap deterministic post-passes, so they stay uncached. Attribution runs last so it
    sees every endpoint/tracker finding.
    """
    meta = ws.read_meta() if use_cache else None
    findings: list[Finding] = []
    for spec in SCANNERS:
        findings.extend(_run_spec(ws, spec, meta))
    if any(f.kind == "engine" and f.subject == "Unity" for f in findings):
        findings.extend(_run_spec(ws, UNITY_SPEC, meta))
    findings = enrich_native_rvas(findings, ws)
    findings = enrich_dex_locations(findings, ws)
    return enrich_domain_attribution(findings, ws)


def primary_engine(findings: list[Finding]) -> str | None:
    """Pick the most likely engine: highest-confidence 'engine' finding (bundle order breaks ties)."""
    engines = [f for f in findings if f.kind == "engine"]
    if not engines:
        return None
    return max(engines, key=lambda f: _CONFIDENCE_RANK[f.confidence]).subject
