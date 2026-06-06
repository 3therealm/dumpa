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

import enum
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
    manifest_entry: str | None = None
    domain: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in {
            "rva": self.rva, "file_offset": self.file_offset, "file_path": self.file_path,
            "dex_class": self.dex_class, "dex_method": self.dex_method,
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
            dex_method=data.get("dex_method"), manifest_entry=data.get("manifest_entry"),
            domain=data.get("domain"),
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
    abis: list[str] = field(default_factory=_str_list)
    permissions: list[str] = field(default_factory=_str_list)
    signer_cert_sha256: str | None = None
    signing_schemes: list[str] = field(default_factory=_str_list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_sha256": self.input_sha256, "input_size": self.input_size,
            "package": self.package, "version_name": self.version_name,
            "version_code": self.version_code, "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk, "engine": self.engine,
            "abis": list(self.abis), "permissions": list(self.permissions),
            "signer_cert_sha256": self.signer_cert_sha256,
            "signing_schemes": list(self.signing_schemes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppFacts:
        return cls(
            input_sha256=str(data["input_sha256"]), input_size=int(data["input_size"]),
            package=data.get("package"), version_name=data.get("version_name"),
            version_code=data.get("version_code"), min_sdk=data.get("min_sdk"),
            target_sdk=data.get("target_sdk"), engine=data.get("engine"),
            abis=[str(a) for a in data.get("abis", [])],
            permissions=[str(p) for p in data.get("permissions", [])],
            signer_cert_sha256=data.get("signer_cert_sha256"),
            signing_schemes=[str(s) for s in data.get("signing_schemes", [])],
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
        "per_mb": round(len(trackers) / size_mb, 3) if size_mb > 0 else 0.0,
    }
    return out


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
        ("ABIs", ", ".join(f.abis) if f.abis else "none"),
        ("permissions", str(len(f.permissions))),
        ("signer cert", f.signer_cert_sha256 or "unsigned/unknown"),
        ("schemes", "+".join(f.signing_schemes) if f.signing_schemes else "none"),
    ]
    for key, value in rows:
        lines.append(f"- {key}: {value}")
    lines.append("")

    trackers = [x for x in report.findings if x.kind == "tracker"]
    protections = [x for x in report.findings if x.kind == "protection"]
    data_access = [x for x in report.findings if x.kind in ("capability", "data-access")]
    endpoints = [x for x in report.findings if x.kind == "endpoint"]
    others = [x for x in report.findings
              if x.kind not in ("tracker", "protection", "capability", "data-access", "endpoint")]

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
                suffix = f" — {owner}" if owner else ""
                lines.append(f"- {t.subject}{suffix} (confidence: {t.confidence.value})")
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

    lines.append("## Endpoints")
    if not endpoints:
        lines.append("_none_")
    else:
        for x in sorted(endpoints, key=lambda i: i.subject):
            lines.append(f"- {x.subject}")
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
