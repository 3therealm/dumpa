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
from dumpa.core.arsc import ArscTable, parse_arsc_file
from dumpa.core.config import load_config
from dumpa.core.dex import DexFile, parse_dex
from dumpa.core.domains import DomainOwner, build_domain_table
from dumpa.core.elf import ElfFile, parse_elf
from dumpa.core.endpoints import load_endpoint_rules
from dumpa.core.errors import ToolNotFoundError
from dumpa.core.report import Confidence, Evidence, Finding, Location
from dumpa.core.rules import load_builtin
from dumpa.core.tools import ToolRegistry, build_default_registry
from dumpa.core.workspace import Workspace, WorkspaceMeta
from dumpa.scanners import (
    cocos,
    dex,
    dumpcs,
    endpoint,
    engine,
    gametype,
    godot,
    manifest_privacy,
    mediation,
    native,
    native_r2,
    privacy,
    protection,
    resources,
    secret,
    tracker,
    unity,
    unity_assets,
    unity_rules,
)

Scanner = Callable[[Workspace], list[Finding]]


@dataclasses.dataclass(frozen=True)
class ScannerSpec:
    """A scanner plus the rule bundles + tools whose versions gate its cached output."""
    name: str                       # cache id, e.g. "tracker"
    fn: Scanner
    bundles: tuple[str, ...] = ()    # builtin bundle names the scanner consumes
    cacheable: bool = True           # False: always re-run (e.g. networked / TTL-driven)
    tools: tuple[str, ...] = ()      # external tool names whose version gates the cache


# Registration order is the run order; engine detection first so its findings exist
# for primary_engine() and so detail scanners (unity) follow their parent engine.
SCANNERS: tuple[ScannerSpec, ...] = (
    ScannerSpec("engine", engine.scan, ("engines",)),
    ScannerSpec("manifest_privacy", manifest_privacy.scan, ("manifest",)),
    ScannerSpec("tracker", tracker.scan,
                ("trackers", "trackers_exodus", "trackers_trackercontrol")),
    ScannerSpec("mediation", mediation.scan, ("mediation",)),
    ScannerSpec("privacy", privacy.scan, ("privacy",)),
    ScannerSpec("protection", protection.scan, ("protections", "protections_apkid")),
    ScannerSpec("secret", secret.scan, ("secrets",)),
    ScannerSpec("native", native.scan),
    ScannerSpec("dex", dex.scan),
    ScannerSpec("resources", resources.scan),
    ScannerSpec("endpoint", endpoint.scan),
    # gametype resolves a networked, TTL-bound Play genre -> never cached (the
    # dumps/gametype.json sidecar already memoizes the fetch within a workspace).
    ScannerSpec("gametype", gametype.scan, cacheable=False),
    # dumpcs depends on mutable workspace sidecars (`dumps/dump.cs`, gametype.json), not
    # only on the apk input hash, so always run it until those sidecars are part of the key.
    ScannerSpec("dumpcs", dumpcs.scan, dumpcs.const_dumpcs_bundles, cacheable=False),
)
# Unity deep helpers run only when the engine scanner flagged Unity. unity_rules consumes
# the `unity` bundle (cache-keyed on its version); unity.scan and unity_assets.scan are
# code-only (keyed on the dumpa version).
UNITY_SPECS: tuple[ScannerSpec, ...] = (
    ScannerSpec("unity", unity.scan),
    ScannerSpec("unity_rules", unity_rules.scan, ("unity",)),
    ScannerSpec("unity_assets", unity_assets.scan),
)
# Cocos2d-x deep helper runs only when the engine scanner flagged Cocos2d-x. It writes
# decrypted bundle artifacts, so keep it uncached until those sidecars are part of the key.
COCOS_SPECS: tuple[ScannerSpec, ...] = (
    ScannerSpec("cocos", cocos.scan, cacheable=False),
)
# Godot deep helper runs only when the engine scanner flagged Godot. It extracts PCK
# resources, so keep it uncached until those sidecars are part of the key.
GODOT_SPECS: tuple[ScannerSpec, ...] = (
    ScannerSpec("godot", godot.scan, cacheable=False),
)
# Opt-in scanners: not in the always-run pipeline. native_r2 invokes radare2 (slow,
# optional), so it runs only when requested via `analyze --r2` / `scan-native --tool
# radare2`. Its cache key folds in the resolved radare2 version (the `tools` field).
OPTIONAL_SPECS: dict[str, ScannerSpec] = {
    "native_r2": ScannerSpec("native_r2", native_r2.scan, tools=("radare2",)),
}

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
        new_locs: list[Location] | None = None
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


const_dex_xref_tool = "dex-string-xref"
dex_field_xref_tool = "dex-field-xref"
dex_instruction_tool = "dex-instruction"
_DEX_XREF_MAX = 8                       # cap referencers enumerated in evidence


def enrich_dex_locations(findings: list[Finding], ws: Workspace) -> list[Finding]:
    """Backfill DEX location detail on any finding located by offset in a .dex.

    Twin of enrich_native_rvas: a content scanner records (file_path=<dex>, file_offset);
    map each offset through the parsed dex to:
      * its owning class, and method when the offset lands in bytecode (`locate`);
      * for a bytecode hit, the instruction's bytecode offset + accessed field
        (`locate_instruction`);
      * for a string-constant hit, the method(s) that `const-string`-load it
        (`locate_string_xref`) and the static field(s) it initializes
        (`locate_field_init`).
    Each dex is parsed once. Findings already carrying a dex_class, or whose offset resolves
    to nothing, pass through unchanged. Ambiguous (multi-referencer) results are surfaced as
    evidence rather than a single misleading owner.
    """
    cache: dict[str, DexFile | None] = {}

    def mapper(rel: str) -> DexFile | None:
        if rel not in cache:
            path = ws.extracted_dir / rel
            cache[rel] = parse_dex(path) if path.is_file() else None
        return cache[rel]

    out: list[Finding] = []
    for finding in findings:
        new_locs: list[Location] | None = None
        new_evidence: list[Evidence] | None = None
        for i, loc in enumerate(finding.locations):
            if (loc.dex_class is not None or loc.file_offset is None
                    or not loc.file_path or not loc.file_path.endswith(".dex")):
                continue
            dex_file = mapper(loc.file_path)
            if dex_file is None:
                continue
            hit = dex_file.locate(loc.file_offset)
            if hit is not None:
                dex_class, dex_method = hit
                updated = dataclasses.replace(loc, dex_class=dex_class, dex_method=dex_method)
                # Code-offset hits refine to the exact instruction (bytecode offset, opcode)
                # and, for a field-access op, the accessed field. Returns None for a
                # descriptor-string hit, leaving the string case untouched.
                instr = dex_file.locate_instruction(
                    ws.extracted_dir / loc.file_path, loc.file_offset)
                if instr is not None:
                    updated = dataclasses.replace(
                        updated, dex_bytecode_offset=instr.bytecode_offset,
                        dex_field=instr.field)
                    if instr.opcode >= 0:
                        if new_evidence is None:
                            new_evidence = []
                        detail = f" accessing {instr.field}" if instr.field else ""
                        new_evidence.append(Evidence(
                            description=f"instruction op 0x{instr.opcode:02x} at bytecode "
                                        f"+0x{instr.bytecode_offset:x}{detail}",
                            tool=dex_instruction_tool))
                if new_locs is None:
                    new_locs = list(finding.locations)
                new_locs[i] = updated
                continue
            # No structural owner: the offset is in a plain string constant. Resolve the
            # method(s) whose const-string loads it and the static field(s) it initializes.
            refs = dex_file.locate_string_xref(loc.file_offset)
            fields = dex_file.locate_field_init(loc.file_offset)
            if not refs and not fields:
                continue
            updated = loc
            if len(refs) == 1:
                cls, meth = refs[0]
                updated = dataclasses.replace(updated, dex_class=cls, dex_method=meth)
            elif len(refs) > 1:
                # Loaded from several methods: naming one owner would mislead, so surface
                # all referencers as evidence instead.
                if new_evidence is None:
                    new_evidence = []
                shown = ", ".join(f"{c}#{m}" for c, m in refs[:_DEX_XREF_MAX])
                more = "" if len(refs) <= _DEX_XREF_MAX else f" (+{len(refs) - _DEX_XREF_MAX} more)"
                new_evidence.append(Evidence(
                    description=f"string constant loaded by {len(refs)} methods",
                    snippet=shown + more, tool=const_dex_xref_tool))
            if len(fields) == 1:
                desc = fields[0]
                updated = dataclasses.replace(updated, dex_field=desc)
                if updated.dex_class is None and "." in desc:
                    updated = dataclasses.replace(updated, dex_class=desc.rsplit(".", 1)[0])
            elif len(fields) > 1:
                # Initializes several static fields (one shared constant): surface all.
                if new_evidence is None:
                    new_evidence = []
                shown = ", ".join(fields[:_DEX_XREF_MAX])
                more = "" if len(fields) <= _DEX_XREF_MAX else f" (+{len(fields) - _DEX_XREF_MAX} more)"
                new_evidence.append(Evidence(
                    description=f"string constant initializes {len(fields)} static fields",
                    snippet=shown + more, tool=dex_field_xref_tool))
            if updated is not loc:
                if new_locs is None:
                    new_locs = list(finding.locations)
                new_locs[i] = updated
        if new_locs is None and new_evidence is None:
            out.append(finding)
        else:
            out.append(dataclasses.replace(
                finding,
                locations=new_locs if new_locs is not None else finding.locations,
                evidence=(finding.evidence + new_evidence) if new_evidence is not None
                else finding.evidence))
    return out


const_resource_attribution_tool = "resource-attribution"
_ARSC_REL = "resources.arsc"


def enrich_resource_names(findings: list[Finding], ws: Workspace) -> list[Finding]:
    """Attribute findings located by offset inside resources.arsc to the owning resource.

    Twin of enrich_dex_locations: a content scanner records (file_path="resources.arsc",
    file_offset) for a URL/key it matched in the binary table; map that offset through the
    parsed table to the resource (`@string/<name>`) whose value contains it, recorded as
    Evidence. The table is parsed once; findings with no arsc-offset location, or whose
    offset lands outside any string value, pass through unchanged. Idempotent — re-running
    on an already-attributed finding adds nothing.
    """
    if not any(loc.file_path == _ARSC_REL and loc.file_offset is not None
               for f in findings for loc in f.locations):
        return findings
    table: ArscTable | None = parse_arsc_file(ws.extracted_dir / _ARSC_REL)
    if table is None:
        return findings

    out: list[Finding] = []
    for finding in findings:
        names: list[str] = []
        for loc in finding.locations:
            if loc.file_path != _ARSC_REL or loc.file_offset is None:
                continue
            hit = table.locate(loc.file_offset)
            if hit is not None and hit[0] not in names:
                names.append(hit[0])
        if not names:
            out.append(finding)
            continue
        evidence = list(finding.evidence)
        for name in names:
            ev = Evidence(description=f"in resource @string/{name}",
                          snippet=name, tool=const_resource_attribution_tool)
            if not _has_equivalent_evidence(evidence, ev):
                evidence.append(ev)
        out.append(dataclasses.replace(finding, evidence=evidence)
                   if len(evidence) != len(finding.evidence) else finding)
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


def enrich_endpoint_purpose(findings: list[Finding], ws: Workspace) -> list[Finding]:
    """Tag each `endpoint` finding with a functional `purpose` and dedupe by host. Idempotent.

    Two jobs, both additive/order-preserving:
    - classify (host + the `paths` attribute) -> a `purpose` attribute via the endpoints
      bundle, set only when matched and absent;
    - dedupe endpoint findings by subject (first wins). The endpoint scanner runs before the
      engine deep helpers, so the loose-tree finding wins over a Godot-emitted duplicate; a
      host seen only inside a PCK keeps its single finding. `ws` is unused (table is built from
      in-repo bundles), kept for signature parity with the sibling enrich passes.
    """
    table = load_endpoint_rules()
    out: list[Finding] = []
    seen: set[str] = set()
    for f in findings:
        if f.kind != "endpoint":
            out.append(f)
            continue
        subject = f.subject.lower()
        if subject in seen:
            continue                     # dedupe: first endpoint finding per host wins
        seen.add(subject)
        if "purpose" in f.attributes or len(table) == 0:
            out.append(f)
            continue
        paths = tuple(p for p in f.attributes.get("paths", "").split("; ") if p)
        purpose = table.classify(f.subject, paths)
        if purpose is None:
            out.append(f)
            continue
        attrs = dict(f.attributes)
        attrs["purpose"] = purpose
        out.append(dataclasses.replace(f, attributes=attrs))
    return out


def _tool_versions(registry: ToolRegistry | None, tools: tuple[str, ...]) -> dict[str, str]:
    """Resolve each tool's version for the cache key; 'absent' when it cannot be found."""
    if not tools or registry is None:
        return {}
    out: dict[str, str] = {}
    for name in tools:
        try:
            out[name] = registry.resolve(name).version or "?"
        except ToolNotFoundError:
            out[name] = "absent"
    return out


def _run_spec(ws: Workspace, spec: ScannerSpec, meta: WorkspaceMeta | None,
              registry: ToolRegistry | None = None) -> list[Finding]:
    """Run one scanner, serving from / writing to the content-hash cache when possible.

    Caching is active only for a marked workspace (meta present); without it there is no
    input hash to key on, so the scanner just runs (the case for in-memory unit tests).
    A scanner that invokes an external tool keys its cache on that tool's version too.
    """
    if meta is None or not spec.cacheable:
        return list(spec.fn(ws))
    key = cache.compute_scanner_key(
        meta.input_sha256, {b: load_builtin(b).version for b in spec.bundles},
        _tool_versions(registry, spec.tools),
    )
    cached = cache.read_scanner_cache(ws, spec.name, key)
    if cached is not None:
        return cached
    produced = list(spec.fn(ws))
    cache.write_scanner_cache(ws, spec.name, key, produced)
    return produced


def run_all(ws: Workspace, *, use_cache: bool = True, extra: tuple[str, ...] = (),
            registry: ToolRegistry | None = None) -> list[Finding]:
    """Run every registered scanner over the workspace and concatenate their findings.

    Per-scanner findings are memoized under a content-hash key (input + dumpa + rule-bundle
    versions + any tool version); pass use_cache=False to force a fresh scan. `extra` names
    opt-in scanners from OPTIONAL_SPECS to append (e.g. "native_r2" for `analyze --r2`).
    `enrich_native_rvas`, `enrich_dex_locations`, `enrich_resource_names`,
    `enrich_domain_attribution`, and `enrich_endpoint_purpose` run on the assembled list
    every time — cheap deterministic post-passes, so they stay uncached. Domain attribution
    then endpoint-purpose run last so they see every endpoint/tracker finding (including
    engine-helper-emitted endpoints).
    """
    meta = ws.read_meta() if use_cache else None
    if registry is None:
        registry = build_default_registry(load_config().tool_paths)
    findings: list[Finding] = []
    for spec in SCANNERS:
        findings.extend(_run_spec(ws, spec, meta, registry))
    if any(f.kind == "engine" and f.subject == "Unity" for f in findings):
        for spec in UNITY_SPECS:
            findings.extend(_run_spec(ws, spec, meta, registry))
    if any(f.kind == "engine" and f.subject == "Cocos2d-x" for f in findings):
        for spec in COCOS_SPECS:
            findings.extend(_run_spec(ws, spec, meta, registry))
    if any(f.kind == "engine" and f.subject == "Godot" for f in findings):
        for spec in GODOT_SPECS:
            findings.extend(_run_spec(ws, spec, meta, registry))
    for name in extra:
        spec = OPTIONAL_SPECS.get(name)
        if spec is not None:
            findings.extend(_run_spec(ws, spec, meta, registry))
    findings = enrich_native_rvas(findings, ws)
    findings = enrich_dex_locations(findings, ws)
    findings = enrich_resource_names(findings, ws)
    findings = enrich_domain_attribution(findings, ws)
    return enrich_endpoint_purpose(findings, ws)


def primary_engine(findings: list[Finding]) -> str | None:
    """Pick the most likely engine: highest-confidence 'engine' finding (bundle order breaks ties)."""
    engines = [f for f in findings if f.kind == "engine"]
    if not engines:
        return None
    return max(engines, key=lambda f: _CONFIDENCE_RANK[f.confidence]).subject


def game_types(findings: list[Finding]) -> list[str]:
    """Resolved Play genres, in scanner order, for AppFacts.game_types."""
    return [f.subject for f in findings if f.kind == "game-type"]
