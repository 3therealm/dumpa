"""The unified finding/report model — the spine every scanner and exporter shares.

Every scanner is a pure function `(workspace) -> list[Finding]`; every exporter
(JSON, Markdown, ...) consumes one `Report`. There are no per-scanner report shapes.
This module is deliberately pure: model + (de)serialization + rendering only, no
external-tool imports, so it sits at the bottom of the dependency graph. The builder
that fills a report from a real apk lives in `dumpa.reporting`.

A `Finding` carries a kind, a subject, a confidence, an evidence list, and
zero-or-more locations (a native RVA, a file offset, a DEX class/method, a manifest
entry, an asset path, or a domain) — whichever apply to that kind of finding.
"""

from __future__ import annotations

import csv
import enum
import html
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

const_report_schema_version = 1


class Confidence(enum.StrEnum):
    """How sure a scanner is about a finding."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingState(enum.StrEnum):
    """How strongly the evidence binds a finding to actual behaviour (false-positive control).

    present        the artifact exists (e.g. a class/lib/asset is in the apk)
    referenced     code references it (a call site / import was found)
    initialized    it is set up at runtime (constructor / init call observed statically)
    network-observed  dynamic analysis saw it contact the network
    """
    PRESENT = "present"
    REFERENCED = "referenced"
    INITIALIZED = "initialized"
    NETWORK_OBSERVED = "network-observed"


def _str_list() -> list[str]:
    return []


def _evidence_list() -> list[Evidence]:
    return []


def _location_list() -> list[Location]:
    return []


def _finding_list() -> list[Finding]:
    return []


def _str_map() -> dict[str, str]:
    return {}


@dataclass(frozen=True)
class Location:
    """Where a finding lives. Only the fields relevant to its kind are populated."""
    rva: int | None = None
    file_offset: int | None = None
    file_path: str | None = None       # asset/lib/resource path inside the apk
    dex_class: str | None = None
    dex_method: str | None = None
    dex_field: str | None = None        # "DefiningClass.name" — accessed/initialized field
    dex_bytecode_offset: int | None = None   # instruction offset in 16-bit code units
    manifest_entry: str | None = None
    domain: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in {
            "rva": self.rva, "file_offset": self.file_offset, "file_path": self.file_path,
            "dex_class": self.dex_class, "dex_method": self.dex_method,
            "dex_field": self.dex_field, "dex_bytecode_offset": self.dex_bytecode_offset,
            "manifest_entry": self.manifest_entry, "domain": self.domain,
        }.items():
            if value is not None:
                out[key] = value
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Location:
        return cls(
            rva=data.get("rva"), file_offset=data.get("file_offset"),
            file_path=data.get("file_path"), dex_class=data.get("dex_class"),
            dex_method=data.get("dex_method"), dex_field=data.get("dex_field"),
            dex_bytecode_offset=data.get("dex_bytecode_offset"),
            manifest_entry=data.get("manifest_entry"), domain=data.get("domain"),
        )


@dataclass(frozen=True)
class Evidence:
    """Why a finding was reported, so users can audit false positives."""
    description: str
    snippet: str | None = None
    file_sha256: str | None = None
    tool: str | None = None
    rule_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"description": self.description}
        for key, value in {
            "snippet": self.snippet, "file_sha256": self.file_sha256,
            "tool": self.tool, "rule_version": self.rule_version,
        }.items():
            if value is not None:
                out[key] = value
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        return cls(
            description=str(data["description"]), snippet=data.get("snippet"),
            file_sha256=data.get("file_sha256"), tool=data.get("tool"),
            rule_version=data.get("rule_version"),
        )


@dataclass(frozen=True)
class Finding:
    """One thing a scanner found (a tracker, protection, engine, ...)."""
    kind: str
    subject: str
    confidence: Confidence
    state: FindingState = FindingState.PRESENT
    # kind-specific metadata, e.g. tracker category / SDK owner / purpose.
    attributes: dict[str, str] = field(default_factory=_str_map)
    evidence: list[Evidence] = field(default_factory=_evidence_list)
    locations: list[Location] = field(default_factory=_location_list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "subject": self.subject,
            "confidence": self.confidence.value,
            "state": self.state.value,
            "attributes": dict(self.attributes),
            "evidence": [e.to_dict() for e in self.evidence],
            "locations": [loc.to_dict() for loc in self.locations],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            kind=str(data["kind"]), subject=str(data["subject"]),
            confidence=Confidence(str(data["confidence"])),
            state=FindingState(str(data.get("state", FindingState.PRESENT.value))),
            attributes={str(k): str(v) for k, v in dict(data.get("attributes", {})).items()},
            evidence=[Evidence.from_dict(e) for e in data.get("evidence", [])],
            locations=[Location.from_dict(loc) for loc in data.get("locations", [])],
        )


@dataclass(frozen=True)
class AppFacts:
    """The cheap, scanner-free facts about an app (the report header)."""
    input_sha256: str
    input_size: int
    package: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    engine: str | None = None                       # reserved for Phase 4
    game_types: list[str] = field(default_factory=_str_list)   # Play genres, primary first
    abis: list[str] = field(default_factory=_str_list)
    permissions: list[str] = field(default_factory=_str_list)
    signer_cert_sha256: str | None = None
    signing_schemes: list[str] = field(default_factory=_str_list)
    signer_is_debug: bool | None = None             # signed with the Android debug cert
    debuggable: bool | None = None                  # from the parsed manifest
    allow_backup: bool | None = None
    exported_component_count: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_sha256": self.input_sha256, "input_size": self.input_size,
            "package": self.package, "version_name": self.version_name,
            "version_code": self.version_code, "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk, "engine": self.engine,
            "game_types": list(self.game_types),
            "abis": list(self.abis), "permissions": list(self.permissions),
            "signer_cert_sha256": self.signer_cert_sha256,
            "signing_schemes": list(self.signing_schemes),
            "signer_is_debug": self.signer_is_debug,
            "debuggable": self.debuggable, "allow_backup": self.allow_backup,
            "exported_component_count": self.exported_component_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppFacts:
        return cls(
            input_sha256=str(data["input_sha256"]), input_size=int(data["input_size"]),
            package=data.get("package"), version_name=data.get("version_name"),
            version_code=data.get("version_code"), min_sdk=data.get("min_sdk"),
            target_sdk=data.get("target_sdk"), engine=data.get("engine"),
            game_types=[str(g) for g in data.get("game_types", [])],
            abis=[str(a) for a in data.get("abis", [])],
            permissions=[str(p) for p in data.get("permissions", [])],
            signer_cert_sha256=data.get("signer_cert_sha256"),
            signing_schemes=[str(s) for s in data.get("signing_schemes", [])],
            signer_is_debug=data.get("signer_is_debug"),
            debuggable=data.get("debuggable"), allow_backup=data.get("allow_backup"),
            exported_component_count=data.get("exported_component_count"),
        )


@dataclass(frozen=True)
class Report:
    """One analysis report: facts header + findings + provenance."""
    dumpa_version: str
    created: str
    input_path: str
    facts: AppFacts
    schema_version: int = const_report_schema_version
    tool_versions: dict[str, str] = field(default_factory=_str_map)
    findings: list[Finding] = field(default_factory=_finding_list)
    warnings: list[str] = field(default_factory=_str_list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "dumpa_version": self.dumpa_version,
            "created": self.created,
            "input_path": self.input_path,
            "facts": self.facts.to_dict(),
            "tool_versions": dict(self.tool_versions),
            "findings": [f.to_dict() for f in self.findings],
            "warnings": list(self.warnings),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Report:
        return cls(
            schema_version=int(data["schema_version"]),
            dumpa_version=str(data["dumpa_version"]),
            created=str(data["created"]),
            input_path=str(data["input_path"]),
            facts=AppFacts.from_dict(data["facts"]),
            tool_versions={str(k): str(v) for k, v in dict(data.get("tool_versions", {})).items()},
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            warnings=[str(w) for w in data.get("warnings", [])],
        )


def to_json(report: Report) -> str:
    """Serialize a report to a stable, pretty JSON string."""
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"


def write_json(report: Report, path: Path) -> None:
    """Write a report as JSON, creating the parent directory if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(report), encoding="UTF-8")


def read_json(path: Path) -> Report | None:
    """Load a report from JSON; None if absent or malformed."""
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="UTF-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(loaded, dict):
        return None
    try:
        return Report.from_dict(cast("dict[str, Any]", loaded))
    except (KeyError, TypeError, ValueError):
        return None


_AD_CATEGORIES = frozenset({"ads", "ad mediation"})
_MEDIATION_CATEGORY = "ad mediation"


@dataclass(frozen=True)
class CompanyRollup:
    """Per-company view of the tracker findings owned by one company."""
    owner: str
    trackers: list[str]        # subjects, sorted-distinct
    categories: list[str]      # sorted-distinct
    domains: list[str]         # sorted-distinct, from grouped findings' Location.domain
    mediation_adapters: int    # count of grouped trackers with category == "ad mediation"


def companies(report: Report) -> dict[str, CompanyRollup]:
    """Group tracker findings by their `owner` attribute into per-company rollups.

    Only `kind == "tracker"` findings carrying an `owner` attribute participate;
    unattributed trackers are skipped. For each owner, collect sorted-distinct subjects,
    categories, and Location.domain values, plus a count of trackers whose
    category == "ad mediation". Keyed by owner string.
    """
    subjects: dict[str, set[str]] = {}
    categories: dict[str, set[str]] = {}
    domains: dict[str, set[str]] = {}
    mediation: dict[str, set[str]] = {}
    for finding in report.findings:
        if finding.kind != "tracker":
            continue
        owner = finding.attributes.get("owner")
        if not owner:
            continue
        subjects.setdefault(owner, set()).add(finding.subject)
        categories.setdefault(owner, set())
        domains.setdefault(owner, set())
        mediation.setdefault(owner, set())
        category = finding.attributes.get("category")
        if category:
            categories[owner].add(category)
        if category == _MEDIATION_CATEGORY:
            mediation[owner].add(finding.subject)
        for loc in finding.locations:
            if loc.domain:
                domains[owner].add(loc.domain)
    return {
        owner: CompanyRollup(
            owner=owner,
            trackers=sorted(subjects[owner]),
            categories=sorted(categories[owner]),
            domains=sorted(domains[owner]),
            mediation_adapters=len(mediation[owner]),
        )
        for owner in subjects
    }


def density_score(report: Report) -> dict[str, float]:
    """Ad/tracker density metrics derived from the tracker findings."""
    trackers = [f for f in report.findings if f.kind == "tracker"]
    owners = {f.attributes["owner"] for f in trackers if f.attributes.get("owner")}
    ad_sdks = [f for f in trackers if f.attributes.get("category") in _AD_CATEGORIES]
    size_mb = report.facts.input_size / (1024 * 1024)
    out: dict[str, float] = {
        "trackers": len(trackers),
        "companies": len(owners),
        "ad_sdks": len(ad_sdks),
        "mediation_adapters": len([f for f in trackers
                                   if f.attributes.get("category") == _MEDIATION_CATEGORY]),
        "per_mb": round(len(trackers) / size_mb, 3) if size_mb > 0 else 0.0,
    }
    return out


# Likely data use per tracker taxonomy (the Phase 5 SDK data-use mapping). A per-SDK
# `data_use` rule attribute overrides this default; otherwise the category answers
# "what does an SDK of this kind likely collect/use".
TRACKER_DATA_USE_BY_CATEGORY: dict[str, str] = {
    "ads": "device & ad IDs, ad interactions",
    "ad mediation": "device & ad IDs, ad interactions",
    "ad mediation adapter": "device & ad IDs, ad interactions",
    "analytics": "app activity, device IDs",
    "attribution": "install referrer, device IDs",
    "crash reporting": "diagnostics, device state",
    "remote config": "app config, device IDs",
    "push messaging": "device tokens",
    "A/B testing": "app activity, device IDs",
    "social login or sharing": "account identity, social graph",
    "anti-fraud": "device fingerprint, behavior signals",
    "consent management": "consent state",
}


def tracker_data_use(finding: Finding) -> str:
    """A tracker finding's likely data use: its `data_use` attribute, else the category default."""
    explicit = finding.attributes.get("data_use")
    if explicit:
        return explicit
    return TRACKER_DATA_USE_BY_CATEGORY.get(finding.attributes.get("category", ""), "")


# Likely purpose per tracker taxonomy (the Phase 5 SDK purpose mapping). A per-SDK
# `purpose` rule attribute overrides this default; otherwise the category answers
# "why does an app integrate an SDK of this kind".
TRACKER_PURPOSE_BY_CATEGORY: dict[str, str] = {
    "ads": "serve in-app advertising",
    "ad mediation": "auction ad inventory across networks",
    "ad mediation adapter": "bridge a mediator to an ad network",
    "analytics": "measure app usage & behavior",
    "attribution": "attribute installs & ad spend",
    "crash reporting": "report crashes & stability",
    "remote config": "remotely configure app behavior",
    "push messaging": "deliver push notifications",
    "A/B testing": "run experiments & feature flags",
    "social login or sharing": "social sign-in & sharing",
    "anti-fraud": "detect fraud & abuse",
    "consent management": "collect & manage user consent",
}

# Product family per tracker subject (the Phase 5 SDK product mapping). Maps a detected
# SDK to the marketed product it belongs to — useful where one owner ships several SDKs
# (Google -> Firebase / AdMob / GA). A per-SDK `product` rule attribute overrides this;
# subjects absent here fall back to the subject itself (product == SDK name).
TRACKER_PRODUCT_BY_SUBJECT: dict[str, str] = {
    "Firebase Analytics": "Firebase",
    "Firebase Crashlytics": "Firebase",
    "Firebase Cloud Messaging": "Firebase",
    "Firebase Remote Config": "Firebase",
    "Google Analytics": "Google Analytics",
    "Google AdMob / Mobile Ads": "Google Mobile Ads",
    "Google UMP": "Google User Messaging Platform",
    "Unity LevelPlay / ironSource": "Unity LevelPlay",
}


def tracker_purpose(finding: Finding) -> str:
    """A tracker finding's purpose: its `purpose` attribute, else the category default."""
    explicit = finding.attributes.get("purpose")
    if explicit:
        return explicit
    return TRACKER_PURPOSE_BY_CATEGORY.get(finding.attributes.get("category", ""), "")


def tracker_product(finding: Finding) -> str:
    """A tracker finding's product family: its `product` attribute, else the subject map,
    else the subject itself (the SDK name is its own product)."""
    explicit = finding.attributes.get("product")
    if explicit:
        return explicit
    return TRACKER_PRODUCT_BY_SUBJECT.get(finding.subject, finding.subject)


_MEDIATION_ADAPTER_KIND = "mediation-adapter"


@dataclass(frozen=True)
class MediationEdge:
    """One mediator->network link. `confirmed` = a per-network adapter class was found;
    otherwise it is a co-presence inference (the mediator and the ad network both ship,
    but no adapter class tied them together)."""
    network: str
    confirmed: bool


@dataclass(frozen=True)
class MediationGraph:
    """A mediation SDK and the ad networks it routes to, derived from the findings."""
    mediator: str
    edges: list[MediationEdge]      # sorted-distinct by network


def mediation_graph(report: Report) -> dict[str, MediationGraph]:
    """Build a mediator -> [networks] graph from the tracker + mediation-adapter findings.

    Nodes are the mediation SDKs: every `mediation-adapter` finding's `mediator` plus every
    tracker finding with category == "ad mediation". Edges come from two signals, strongest
    first:

    * **confirmed** — a `mediation-adapter` finding names this mediator routing to a network;
    * **co-presence** — only when a mediator has *no* confirmed adapter, the co-present ad
      networks (tracker findings with category in {ads, ad mediation}, minus the mediator
      itself) are added as unconfirmed inferences.

    Keyed by mediator name. A mediator with neither confirmed adapters nor any co-present ad
    network is still returned (empty edges) so the report can show it stands alone.
    """
    confirmed: dict[str, set[str]] = {}
    for f in report.findings:
        if f.kind != _MEDIATION_ADAPTER_KIND:
            continue
        mediator = f.attributes.get("mediator")
        network = f.attributes.get("network")
        if mediator and network:
            confirmed.setdefault(mediator, set()).add(network)

    mediator_subjects = {f.subject for f in report.findings
                         if f.kind == "tracker" and f.attributes.get("category") == _MEDIATION_CATEGORY}
    ad_networks = sorted({f.subject for f in report.findings
                          if f.kind == "tracker" and f.attributes.get("category") in _AD_CATEGORIES})

    graph: dict[str, MediationGraph] = {}
    for mediator in sorted(set(confirmed) | mediator_subjects):
        if confirmed.get(mediator):
            edges = [MediationEdge(network=n, confirmed=True)
                     for n in sorted(confirmed[mediator])]
        else:
            edges = [MediationEdge(network=n, confirmed=False)
                     for n in ad_networks if n != mediator]
        graph[mediator] = MediationGraph(mediator=mediator, edges=edges)
    return graph


def report_domains(report: Report, *, trackers_only: bool = False) -> list[str]:
    """Sorted unique domain strings (string-only helper; CSV/grouped views use domain_records()).

    Default (trackers_only=False) = all hosts: endpoint subjects UNION every Location.domain.
    trackers_only=True -> only tracker-owned hosts:
        - a Location.domain present on a tracker finding, OR
        - an endpoint finding's subject when that endpoint carries an `owner` attribute.
    """
    domains: set[str] = set()
    for finding in report.findings:
        if trackers_only:
            if finding.kind == "tracker":
                for loc in finding.locations:
                    if loc.domain:
                        domains.add(loc.domain)
            elif finding.kind == "endpoint" and finding.attributes.get("owner"):
                domains.add(finding.subject)
        else:
            if finding.kind == "endpoint":
                domains.add(finding.subject)
            for loc in finding.locations:
                if loc.domain:
                    domains.add(loc.domain)
    return sorted(d for d in domains if d)


_BLOCKLIST_UNATTRIBUTED = "(unattributed)"


def render_blocklist(report: Report, fmt: str, *, trackers_only: bool = False) -> str:
    """Render a domain blocklist in `fmt`, scoped per `trackers_only`.

    fmt line shapes:
      hosts          -> '0.0.0.0 <domain>'
      adguard        -> '||<domain>^'
      nextdns        -> bare '<domain>'
      rethinkdns     -> bare '<domain>' with a leading '! dumpa' comment line
      trackercontrol -> '0.0.0.0 <domain>' grouped under '# <owner>' headers (via domain_records())
    """
    if fmt == "trackercontrol":
        scoped = set(report_domains(report, trackers_only=trackers_only))
        by_owner: dict[str, set[str]] = {}
        for rec in domain_records(report):
            if rec.domain not in scoped:
                continue
            by_owner.setdefault(rec.owner or _BLOCKLIST_UNATTRIBUTED, set()).add(rec.domain)
        lines: list[str] = []
        for owner in sorted(by_owner):
            lines.append(f"# {owner}")
            lines.extend(f"0.0.0.0 {d}" for d in sorted(by_owner[owner]))
        return "\n".join(lines) + "\n" if lines else ""

    domains = report_domains(report, trackers_only=trackers_only)
    if not domains:
        return ""
    if fmt == "adguard":
        lines = [f"||{d}^" for d in domains]
    elif fmt == "nextdns":
        lines = list(domains)
    elif fmt == "rethinkdns":
        lines = ["! dumpa", *domains]
    else:  # hosts
        lines = [f"0.0.0.0 {d}" for d in domains]
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class DomainRecord:
    """One attributed domain: ownership + first observed location.

    The single source for the domains CSV and (section-06) grouped blocklists, since
    report_domains() returns only list[str] and loses owner/category/subject/location.
    """
    domain: str
    owner: str | None
    category: str | None
    subject: str | None          # owning tracker subject, if attributed
    first_file: str | None
    first_offset: int | None


def domain_records(report: Report) -> list[DomainRecord]:
    """One DomainRecord per unique domain across the report, sorted by domain.

    Collects every domain from endpoint finding subjects and every Location.domain on
    any finding. For each domain: `subject` is the owning tracker subject when a tracker
    finding carries that domain in a Location; owner/category come from whichever finding
    carries the domain (tracker first, then endpoint whose subject == domain); and
    first_file/first_offset come from the first domain-bearing Location in report order.
    """
    domains: set[str] = set()
    for finding in report.findings:
        if finding.kind == "endpoint":
            domains.add(finding.subject)
        for loc in finding.locations:
            if loc.domain:
                domains.add(loc.domain)

    records: list[DomainRecord] = []
    for domain in sorted(d for d in domains if d):
        owner: str | None = None
        category: str | None = None
        subject: str | None = None
        first_file: str | None = None
        first_offset: int | None = None
        located = False
        # Tracker carriers win on subject + owner/category (tracker-first).
        for finding in report.findings:
            if finding.kind != "tracker":
                continue
            if any(loc.domain == domain for loc in finding.locations):
                if subject is None:
                    subject = finding.subject
                if owner is None:
                    owner = finding.attributes.get("owner")
                if category is None:
                    category = finding.attributes.get("category")
        # Endpoint fallback for owner/category only if no tracker supplied them.
        if owner is None or category is None:
            for finding in report.findings:
                if finding.kind == "endpoint" and finding.subject == domain:
                    if owner is None:
                        owner = finding.attributes.get("owner")
                    if category is None:
                        category = finding.attributes.get("category")
        # First domain-bearing location in report order.
        for finding in report.findings:
            for loc in finding.locations:
                if loc.domain == domain:
                    first_file = loc.file_path
                    first_offset = loc.file_offset
                    located = True
                    break
            if located:
                break
        records.append(DomainRecord(
            domain=domain, owner=owner, category=category, subject=subject,
            first_file=first_file, first_offset=first_offset,
        ))
    return records


def _csv_writer(header: list[str]) -> tuple[io.StringIO, Any]:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(header)
    return buf, writer


def render_trackers_csv(report: Report) -> str:
    """CSV, one row per tracker finding (kind == 'tracker'), sorted by subject.

    header: subject,owner,category,confidence,state,domains,files
    domains/files are ';'-joined sorted-distinct non-empty Location values.
    """
    buf, writer = _csv_writer(
        ["subject", "owner", "category", "confidence", "state", "domains", "files"])
    trackers = sorted((f for f in report.findings if f.kind == "tracker"),
                      key=lambda f: f.subject)
    for f in trackers:
        domains = sorted({loc.domain for loc in f.locations if loc.domain})
        files = sorted({loc.file_path for loc in f.locations if loc.file_path})
        writer.writerow([
            f.subject, f.attributes.get("owner", ""), f.attributes.get("category", ""),
            f.confidence.value, f.state.value, ";".join(domains), ";".join(files),
        ])
    return buf.getvalue()


def render_domains_csv(report: Report) -> str:
    """CSV, one row per unique domain (sorted), driven by domain_records(report).

    header: domain,owner,category,subject,first_file,first_offset
    None fields render as empty string.
    """
    buf, writer = _csv_writer(
        ["domain", "owner", "category", "subject", "first_file", "first_offset"])
    for r in domain_records(report):
        writer.writerow([
            r.domain, r.owner or "", r.category or "", r.subject or "",
            r.first_file or "", "" if r.first_offset is None else r.first_offset,
        ])
    return buf.getvalue()


def _flag_label(value: bool | None) -> str:
    """Render an optional manifest boolean flag for the report."""
    if value is None:
        return "?"
    return "yes" if value else "no"


def render_markdown(report: Report) -> str:
    """Render a human-readable Markdown view of a report."""
    f = report.facts
    lines: list[str] = []
    title = f.package or Path(report.input_path).name
    lines.append(f"# dumpa report — {title}")
    lines.append("")
    lines.append(f"- input: `{report.input_path}`")
    lines.append(f"- sha256: `{f.input_sha256}`")
    lines.append(f"- size: {f.input_size / (1024 * 1024):.2f} MB")
    lines.append(f"- created: {report.created}")
    lines.append("")
    lines.append("## App")
    version = f.version_name or "?"
    if f.version_code:
        version += f" ({f.version_code})"
    rows = [
        ("package", f.package or "unknown"),
        ("version", version),
        ("minSdk", f.min_sdk or "?"),
        ("targetSdk", f.target_sdk or "?"),
        ("engine", f.engine or "n/a"),
        ("game type", ", ".join(f.game_types) if f.game_types else "n/a"),
        ("ABIs", ", ".join(f.abis) if f.abis else "none"),
        ("permissions", str(len(f.permissions))),
        ("exported components", str(f.exported_component_count)
         if f.exported_component_count is not None else "?"),
        ("debuggable", _flag_label(f.debuggable)),
        ("allowBackup", _flag_label(f.allow_backup)),
        ("signer cert", f.signer_cert_sha256 or "unsigned/unknown"),
        ("schemes", "+".join(f.signing_schemes) if f.signing_schemes else "none"),
        ("debug cert", _flag_label(f.signer_is_debug)),
    ]
    for key, value in rows:
        lines.append(f"- {key}: {value}")
    lines.append("")

    trackers = [x for x in report.findings if x.kind == "tracker"]
    protections = [x for x in report.findings if x.kind == "protection"]
    secrets = [x for x in report.findings if x.kind == "secret"]
    data_access = [x for x in report.findings if x.kind in ("capability", "data-access")]
    data_safety = [x for x in report.findings if x.kind == "data-safety"]
    data_safety_gaps = [x for x in report.findings if x.kind == "data-safety-gap"]
    endpoints = [x for x in report.findings if x.kind == "endpoint"]
    ip_endpoints = [x for x in report.findings if x.kind == "ip-endpoint"]
    native_libs = [x for x in report.findings if x.kind == "native"]
    native_symbols = [x for x in report.findings if x.kind == "native-symbol"]
    dexes = [x for x in report.findings if x.kind == "dex"]
    ad_id_attrs = [x for x in report.findings if x.kind == "ad-id-attribution"]
    _sectioned = ("tracker", "protection", "secret", "capability", "data-access",
                  "data-safety", "data-safety-gap", "endpoint", "ip-endpoint", "native",
                  "native-symbol", "dex", "mediation-adapter", "ad-id-attribution")
    others = [x for x in report.findings if x.kind not in _sectioned]

    lines.append("## Trackers")
    if not trackers:
        lines.append("_none_")
        lines.append("")
    else:
        d = density_score(report)
        lines.append(f"{int(d['trackers'])} tracker(s) from {int(d['companies'])} "
                     f"company(ies); {int(d['ad_sdks'])} ad SDK(s); {d['per_mb']} trackers/MB")
        lines.append("")
        by_category: dict[str, list[Finding]] = {}
        for t in trackers:
            by_category.setdefault(t.attributes.get("category", "uncategorized"), []).append(t)
        for category in sorted(by_category):
            lines.append(f"### {category}")
            for t in sorted(by_category[category], key=lambda x: x.subject):
                owner = t.attributes.get("owner")
                product = tracker_product(t)
                purpose = tracker_purpose(t)
                data_use = tracker_data_use(t)
                suffix = f" — {owner}" if owner else ""
                prod = f" ({product})" if product and product != t.subject else ""
                why = f" — {purpose}" if purpose else ""
                use = f" [data use: {data_use}]" if data_use else ""
                lines.append(f"- {t.subject}{prod}{suffix}{why}{use} "
                             f"(confidence: {t.confidence.value})")
            lines.append("")
        rollups = companies(report)
        if rollups:
            parts = [f"{r.owner} ({len(r.trackers)})"
                     for r in sorted(rollups.values(), key=lambda r: r.owner)]
            lines.append(f"companies: {', '.join(parts)}")
            lines.append("")

    lines.append("## Ad mediation")
    graph = mediation_graph(report)
    if not graph:
        lines.append("_none_")
        lines.append("")
    else:
        for mediator in sorted(graph):
            node = graph[mediator]
            if not node.edges:
                lines.append(f"- {mediator} — no ad networks detected")
                continue
            for edge in node.edges:
                tag = "" if edge.confirmed else " (inferred from co-presence)"
                lines.append(f"- {mediator} → {edge.network}{tag}")
        lines.append("")

    lines.append("## Protections")
    if not protections:
        lines.append("_none_")
    else:
        for p in sorted(protections, key=lambda i: i.subject):
            category = p.attributes.get("category", "")
            tag = f" [{category}]" if category else ""
            lines.append(f"- {p.subject}{tag} (confidence: {p.confidence.value})")
    lines.append("")

    lines.append("## Secrets")
    if not secrets:
        lines.append("_none_")
    else:
        for s in sorted(secrets, key=lambda i: i.subject):
            category = s.attributes.get("category", "")
            tag = f" [{category}]" if category else ""
            lines.append(f"- {s.subject}{tag} (confidence: {s.confidence.value})")
    lines.append("")

    lines.append("## Data access")
    if not data_access:
        lines.append("_none_")
        lines.append("")
    else:
        by_cat: dict[str, list[Finding]] = {}
        for x in data_access:
            by_cat.setdefault(x.attributes.get("category", "other"), []).append(x)
        for category in sorted(by_cat):
            lines.append(f"### {category}")
            for x in sorted(by_cat[category], key=lambda i: i.subject):
                lines.append(f"- {x.subject} ({x.state.value}, confidence: {x.confidence.value})")
            lines.append("")
    for a in ad_id_attrs:
        source = a.attributes.get("source", "unknown")
        lines.append(f"- AD_ID likely added by: {source} "
                     f"(confidence: {a.confidence.value})")
        lines.append("")

    lines.append("## Data Safety")
    if not data_safety and not data_safety_gaps:
        lines.append("_not listed / lookup disabled_")
        lines.append("")
    else:
        for ds in data_safety:
            lines.append(f"- declared collected: {ds.attributes.get('collected') or 'none'}")
            lines.append(f"- declared shared: {ds.attributes.get('shared') or 'none'}")
        if data_safety_gaps:
            lines.append("")
            lines.append("### Undisclosed (observed but not declared)")
            for g in sorted(data_safety_gaps, key=lambda i: i.subject):
                observed = g.attributes.get("observed_in", "")
                suffix = f" — {observed}" if observed else ""
                lines.append(f"- {g.subject}{suffix} (confidence: {g.confidence.value})")
        lines.append("")

    lines.append("## Endpoints")
    if not endpoints:
        lines.append("_none_")
    else:
        for x in sorted(endpoints, key=lambda i: i.subject):
            purpose = x.attributes.get("purpose")
            country = x.attributes.get("country")
            asn = x.attributes.get("asn")
            tag = f" [{purpose}]" if purpose else ""
            geo = " — " + ", ".join(p for p in (country, asn) if p) if (country or asn) else ""
            lines.append(f"- {x.subject}{tag}{geo}")
    lines.append("")

    lines.append("## IP endpoints")
    if not ip_endpoints:
        lines.append("_none_")
    else:
        for x in sorted(ip_endpoints, key=lambda i: i.subject):
            scope = x.attributes.get("scope", "")
            tag = f" [{scope}]" if scope else ""
            lines.append(f"- {x.subject}{tag}")
    lines.append("")

    lines.append("## Native")
    if not native_libs and not native_symbols:
        lines.append("_none_")
    else:
        counts = {s.subject: s.attributes for s in native_symbols}
        for lib in sorted(native_libs, key=lambda i: i.subject):
            arch = f"{lib.attributes.get('machine', '')} {lib.attributes.get('bitness', '')}".strip()
            extra = counts.get(lib.subject)
            if extra:
                arch += (f" — {extra.get('export_count', '0')} exports, "
                         f"{extra.get('import_count', '0')} imports, "
                         f"{extra.get('section_count', '0')} sections")
            lines.append(f"- {lib.subject}: {arch}")
    lines.append("")

    lines.append("## DEX")
    if not dexes:
        lines.append("_none_")
    else:
        for dx in sorted(dexes, key=lambda i: i.subject):
            a = dx.attributes
            lines.append(f"- {dx.subject}: {a.get('class_count', '0')} classes, "
                         f"{a.get('method_count', '0')} methods, "
                         f"{a.get('field_count', '0')} fields")
    lines.append("")

    lines.append("## Findings")
    if not others:
        lines.append("_none_")
    else:
        for finding in others:
            lines.append(f"- **{finding.kind}**: {finding.subject} "
                         f"(confidence: {finding.confidence.value})")
            for ev in finding.evidence:
                lines.append(f"  - evidence: {ev.description}")
    lines.append("")

    if report.warnings:
        lines.append("## Warnings")
        for warning in report.warnings:
            lines.append(f"- {warning}")
        lines.append("")

    if report.tool_versions:
        lines.append("## Tool versions")
        for name, version in sorted(report.tool_versions.items()):
            lines.append(f"- {name}: {version}")
        lines.append("")

    return "\n".join(lines)


_HTML_STYLE = """\
:root { color-scheme: light dark; }
body { font: 15px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 60rem;
       padding: 0 1rem; }
h1 { font-size: 1.6rem; } h2 { margin-top: 2rem; border-bottom: 1px solid #8884;
       padding-bottom: .2rem; } h3 { font-size: 1.05rem; color: #888; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0; }
th, td { text-align: left; padding: .3rem .6rem; border-bottom: 1px solid #8883;
       vertical-align: top; }
th { white-space: nowrap; color: #888; font-weight: 600; }
code { font-family: ui-monospace, monospace; word-break: break-all; }
.none { color: #888; font-style: italic; }
.meta { color: #888; font-size: .85rem; }
"""


def _h(value: object) -> str:
    """Escape any dynamic value for safe HTML output (markup + attribute context)."""
    return html.escape(str(value), quote=True)


def render_html(report: Report) -> str:
    """Render a self-contained static HTML view of a report (inline CSS, no JS/assets).

    Mirrors render_markdown's sections. Every interpolated value is HTML-escaped via
    `_h`; report text (package names, snippets, domains, ...) is attacker-controlled, so
    nothing reaches the markup unescaped.
    """
    f = report.facts
    title = f.package or Path(report.input_path).name
    out: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>dumpa report — {_h(title)}</title>",
        f"<style>{_HTML_STYLE}</style>",
        "</head><body>",
        f"<h1>dumpa report — {_h(title)}</h1>",
        '<p class="meta">'
        f"input <code>{_h(report.input_path)}</code><br>"
        f"sha256 <code>{_h(f.input_sha256)}</code><br>"
        f"size {f.input_size / (1024 * 1024):.2f} MB · created {_h(report.created)}</p>",
    ]

    version = f.version_name or "?"
    if f.version_code:
        version += f" ({f.version_code})"
    app_rows = [
        ("package", f.package or "unknown"),
        ("version", version),
        ("minSdk", f.min_sdk or "?"),
        ("targetSdk", f.target_sdk or "?"),
        ("engine", f.engine or "n/a"),
        ("game type", ", ".join(f.game_types) if f.game_types else "n/a"),
        ("ABIs", ", ".join(f.abis) if f.abis else "none"),
        ("permissions", str(len(f.permissions))),
        ("exported components", str(f.exported_component_count)
         if f.exported_component_count is not None else "?"),
        ("debuggable", _flag_label(f.debuggable)),
        ("allowBackup", _flag_label(f.allow_backup)),
        ("signer cert", f.signer_cert_sha256 or "unsigned/unknown"),
        ("schemes", "+".join(f.signing_schemes) if f.signing_schemes else "none"),
        ("debug cert", _flag_label(f.signer_is_debug)),
    ]
    out.append("<h2>App</h2><table>")
    out += [f"<tr><th>{_h(k)}</th><td>{_h(v)}</td></tr>" for k, v in app_rows]
    out.append("</table>")

    trackers = [x for x in report.findings if x.kind == "tracker"]
    protections = [x for x in report.findings if x.kind == "protection"]
    secrets = [x for x in report.findings if x.kind == "secret"]
    data_access = [x for x in report.findings if x.kind in ("capability", "data-access")]
    data_safety = [x for x in report.findings if x.kind == "data-safety"]
    data_safety_gaps = [x for x in report.findings if x.kind == "data-safety-gap"]
    endpoints = [x for x in report.findings if x.kind == "endpoint"]
    ip_endpoints = [x for x in report.findings if x.kind == "ip-endpoint"]
    native_libs = [x for x in report.findings if x.kind == "native"]
    native_symbols = [x for x in report.findings if x.kind == "native-symbol"]
    dexes = [x for x in report.findings if x.kind == "dex"]
    ad_id_attrs = [x for x in report.findings if x.kind == "ad-id-attribution"]
    _sectioned = ("tracker", "protection", "secret", "capability", "data-access",
                  "data-safety", "data-safety-gap", "endpoint", "ip-endpoint", "native",
                  "native-symbol", "dex", "mediation-adapter", "ad-id-attribution")
    others = [x for x in report.findings if x.kind not in _sectioned]

    out.append("<h2>Trackers</h2>")
    if not trackers:
        out.append('<p class="none">none</p>')
    else:
        d = density_score(report)
        out.append('<p class="meta">'
                   f"{int(d['trackers'])} tracker(s) from {int(d['companies'])} "
                   f"company(ies); {int(d['ad_sdks'])} ad SDK(s); "
                   f"{d['per_mb']} trackers/MB</p>")
        by_category: dict[str, list[Finding]] = {}
        for t in trackers:
            by_category.setdefault(t.attributes.get("category", "uncategorized"), []).append(t)
        for category in sorted(by_category):
            out.append(f"<h3>{_h(category)}</h3><table>")
            for t in sorted(by_category[category], key=lambda x: x.subject):
                owner = t.attributes.get("owner", "")
                product = tracker_product(t)
                product = "" if product == t.subject else product
                purpose = tracker_purpose(t)
                data_use = tracker_data_use(t)
                out.append(f"<tr><td>{_h(t.subject)}</td><td>{_h(product)}</td>"
                           f"<td>{_h(owner)}</td><td>{_h(purpose)}</td>"
                           f"<td>{_h(data_use)}</td><td>{_h(t.confidence.value)}</td></tr>")
            out.append("</table>")
        rollups = companies(report)
        if rollups:
            parts = [f"{r.owner} ({len(r.trackers)})"
                     for r in sorted(rollups.values(), key=lambda r: r.owner)]
            out.append(f'<p class="meta">companies: {_h(", ".join(parts))}</p>')

    out.append("<h2>Ad mediation</h2>")
    graph = mediation_graph(report)
    if not graph:
        out.append('<p class="none">none</p>')
    else:
        out.append("<table>")
        for mediator in sorted(graph):
            node = graph[mediator]
            if not node.edges:
                out.append(f"<tr><td>{_h(mediator)}</td>"
                           "<td><em>no ad networks detected</em></td></tr>")
                continue
            for edge in node.edges:
                tag = "" if edge.confirmed else " (inferred from co-presence)"
                out.append(f"<tr><td>{_h(mediator)} → {_h(edge.network)}</td>"
                           f"<td>{_h(tag.strip() or 'adapter class')}</td></tr>")
        out.append("</table>")

    out += _html_simple_section("Protections", protections, tag_attr="category")
    out += _html_simple_section("Secrets", secrets, tag_attr="category")

    out.append("<h2>Data access</h2>")
    if not data_access:
        out.append('<p class="none">none</p>')
    else:
        by_cat: dict[str, list[Finding]] = {}
        for x in data_access:
            by_cat.setdefault(x.attributes.get("category", "other"), []).append(x)
        for category in sorted(by_cat):
            out.append(f"<h3>{_h(category)}</h3><table>")
            for x in sorted(by_cat[category], key=lambda i: i.subject):
                out.append(f"<tr><td>{_h(x.subject)}</td><td>{_h(x.state.value)}</td>"
                           f"<td>{_h(x.confidence.value)}</td></tr>")
            out.append("</table>")
    if ad_id_attrs:
        out.append('<p class="meta">')
        for a in ad_id_attrs:
            out.append(f"AD_ID likely added by: {_h(a.attributes.get('source', 'unknown'))} "
                       f"(confidence: {_h(a.confidence.value)})<br>")
        out.append("</p>")

    out.append("<h2>Data Safety</h2>")
    if not data_safety and not data_safety_gaps:
        out.append('<p class="none">not listed / lookup disabled</p>')
    else:
        for ds in data_safety:
            out.append('<table>'
                       f"<tr><th>declared collected</th><td>{_h(ds.attributes.get('collected') or 'none')}</td></tr>"
                       f"<tr><th>declared shared</th><td>{_h(ds.attributes.get('shared') or 'none')}</td></tr>"
                       "</table>")
        if data_safety_gaps:
            out.append("<h3>Undisclosed (observed but not declared)</h3><table>")
            for g in sorted(data_safety_gaps, key=lambda i: i.subject):
                out.append(f"<tr><td>{_h(g.subject)}</td>"
                           f"<td>{_h(g.attributes.get('observed_in', ''))}</td>"
                           f"<td>{_h(g.confidence.value)}</td></tr>")
            out.append("</table>")

    out.append("<h2>Endpoints</h2>")
    if not endpoints:
        out.append('<p class="none">none</p>')
    else:
        out.append("<table>")
        for x in sorted(endpoints, key=lambda i: i.subject):
            purpose = x.attributes.get("purpose", "")
            country = x.attributes.get("country", "")
            asn = x.attributes.get("asn", "")
            geo = ", ".join(p for p in (country, asn) if p)
            out.append(f"<tr><td><code>{_h(x.subject)}</code></td>"
                       f"<td>{_h(purpose)}</td><td>{_h(geo)}</td></tr>")
        out.append("</table>")

    out.append("<h2>IP endpoints</h2>")
    if not ip_endpoints:
        out.append('<p class="none">none</p>')
    else:
        out.append("<table>")
        out += [f"<tr><td><code>{_h(x.subject)}</code></td>"
                f"<td>{_h(x.attributes.get('scope', ''))}</td></tr>"
                for x in sorted(ip_endpoints, key=lambda i: i.subject)]
        out.append("</table>")

    out.append("<h2>Native</h2>")
    if not native_libs and not native_symbols:
        out.append('<p class="none">none</p>')
    else:
        counts = {s.subject: s.attributes for s in native_symbols}
        out.append("<table>")
        for lib in sorted(native_libs, key=lambda i: i.subject):
            arch = f"{lib.attributes.get('machine', '')} {lib.attributes.get('bitness', '')}".strip()
            extra = counts.get(lib.subject)
            if extra:
                arch += (f" — {extra.get('export_count', '0')} exports, "
                         f"{extra.get('import_count', '0')} imports, "
                         f"{extra.get('section_count', '0')} sections")
            out.append(f"<tr><td><code>{_h(lib.subject)}</code></td><td>{_h(arch)}</td></tr>")
        out.append("</table>")

    out.append("<h2>DEX</h2>")
    if not dexes:
        out.append('<p class="none">none</p>')
    else:
        out.append("<table>")
        for dx in sorted(dexes, key=lambda i: i.subject):
            a = dx.attributes
            detail = (f"{a.get('class_count', '0')} classes, "
                      f"{a.get('method_count', '0')} methods, "
                      f"{a.get('field_count', '0')} fields")
            out.append(f"<tr><td><code>{_h(dx.subject)}</code></td><td>{_h(detail)}</td></tr>")
        out.append("</table>")

    out.append("<h2>Findings</h2>")
    if not others:
        out.append('<p class="none">none</p>')
    else:
        out.append("<table>")
        for finding in others:
            ev = "; ".join(e.description for e in finding.evidence)
            out.append(f"<tr><td>{_h(finding.kind)}</td><td>{_h(finding.subject)}</td>"
                       f"<td>{_h(finding.confidence.value)}</td><td>{_h(ev)}</td></tr>")
        out.append("</table>")

    if report.warnings:
        out.append("<h2>Warnings</h2><ul>")
        out += [f"<li>{_h(w)}</li>" for w in report.warnings]
        out.append("</ul>")

    if report.tool_versions:
        out.append("<h2>Tool versions</h2><table>")
        out += [f"<tr><th>{_h(name)}</th><td>{_h(ver)}</td></tr>"
                for name, ver in sorted(report.tool_versions.items())]
        out.append("</table>")

    out.append("</body></html>")
    return "\n".join(out) + "\n"


def _html_simple_section(heading: str, findings: list[Finding], *, tag_attr: str) -> list[str]:
    """Render a flat subject/tag/confidence table section (Protections, Secrets)."""
    out = [f"<h2>{_h(heading)}</h2>"]
    if not findings:
        out.append('<p class="none">none</p>')
        return out
    out.append("<table>")
    for item in sorted(findings, key=lambda i: i.subject):
        tag = item.attributes.get(tag_attr, "")
        out.append(f"<tr><td>{_h(item.subject)}</td><td>{_h(tag)}</td>"
                   f"<td>{_h(item.confidence.value)}</td></tr>")
    out.append("</table>")
    return out
