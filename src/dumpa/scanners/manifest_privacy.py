"""Manifest privacy audit: structural risk signals from AndroidManifest.xml.

Reads the parsed manifest (`core.manifest`) and reports the structural attack surface
the Phase 6 roadmap calls for: exported components, debuggable/backup flags, boot and
install-referrer receivers, and deep links. Permission-*combination* risk is data —
it ships as the `manifest` rule bundle and is applied here too — so this module holds
only the signals that need the component tree.
"""

from __future__ import annotations

from dumpa.core.manifest import Component, ManifestInfo, load_manifest
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.rules import apply_bundle, load_builtin
from dumpa.core.workspace import Workspace

const_manifest_kind = "manifest"
const_manifest_bundle = "manifest"

_BOOT_ACTION = "android.intent.action.BOOT_COMPLETED"
_REFERRER_ACTION = "com.android.vending.INSTALL_REFERRER"
_BROWSABLE = "android.intent.category.BROWSABLE"
_WEB_SCHEMES = ("http", "https")


def _evidence(description: str) -> list[Evidence]:
    return [Evidence(description=description, tool="manifest")]


def _exported_finding(comp: Component) -> Finding:
    explicit = comp.exported is not None
    guarded = comp.permission is not None
    confidence = Confidence.HIGH if explicit and not guarded else Confidence.MEDIUM
    how = "exported" if explicit else "implicitly exported (intent-filter)"
    guard = f"; guarded by {comp.permission}" if guarded else "; no permission guard"
    return Finding(
        kind=const_manifest_kind,
        subject=f"exported {comp.type}: {comp.name}",
        confidence=confidence,
        state=FindingState.PRESENT,
        attributes={
            "category": "exported-component",
            "component_type": comp.type,
            "exported": "explicit" if explicit else "implicit",
            "guarded": "yes" if guarded else "no",
        },
        evidence=_evidence(f"{comp.type} {comp.name} {how}{guard}"),
        locations=[Location(manifest_entry=comp.name)],
    )


def _receiver_findings(comp: Component) -> list[Finding]:
    findings: list[Finding] = []
    actions = {a for f in comp.intent_filters for a in f.actions}
    if _BOOT_ACTION in actions:
        findings.append(Finding(
            kind=const_manifest_kind, subject=f"boot receiver: {comp.name}",
            confidence=Confidence.MEDIUM, state=FindingState.PRESENT,
            attributes={"category": "boot-receiver", "component_type": comp.type},
            evidence=_evidence(f"{comp.name} receives {_BOOT_ACTION}"),
            locations=[Location(manifest_entry=comp.name)],
        ))
    if _REFERRER_ACTION in actions:
        findings.append(Finding(
            kind=const_manifest_kind, subject=f"install-referrer receiver: {comp.name}",
            confidence=Confidence.MEDIUM, state=FindingState.PRESENT,
            attributes={"category": "install-referrer", "component_type": comp.type},
            evidence=_evidence(f"{comp.name} receives {_REFERRER_ACTION}"),
            locations=[Location(manifest_entry=comp.name)],
        ))
    return findings


def _deep_link_findings(comp: Component) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for flt in comp.intent_filters:
        if _BROWSABLE not in flt.categories:
            continue
        for data in flt.data:
            if data.scheme in _WEB_SCHEMES and data.host:
                key = f"{data.scheme}://{data.host}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    kind=const_manifest_kind, subject=f"deep link: {key}",
                    confidence=Confidence.LOW, state=FindingState.PRESENT,
                    attributes={"category": "deep-link", "component_type": comp.type},
                    evidence=_evidence(f"{comp.name} handles browsable {key}"),
                    locations=[Location(manifest_entry=comp.name, domain=data.host)],
                ))
    return findings


def _flag_findings(manifest: ManifestInfo) -> list[Finding]:
    findings: list[Finding] = []
    if manifest.debuggable:
        findings.append(Finding(
            kind=const_manifest_kind, subject="debuggable=true",
            confidence=Confidence.HIGH, state=FindingState.PRESENT,
            attributes={"category": "debug-flag"},
            evidence=_evidence("application android:debuggable=\"true\""),
        ))
    if manifest.allow_backup is True:
        findings.append(Finding(
            kind=const_manifest_kind, subject="allowBackup=true",
            confidence=Confidence.MEDIUM, state=FindingState.PRESENT,
            attributes={"category": "backup-flag"},
            evidence=_evidence("application android:allowBackup=\"true\""),
        ))
    return findings


def scan(ws: Workspace) -> list[Finding]:
    """Audit the manifest for structural privacy/risk signals plus permission combos."""
    manifest = load_manifest(ws)
    if manifest is None:
        return []

    findings: list[Finding] = []
    for comp in manifest.components:
        if comp.exported_effective:
            findings.append(_exported_finding(comp))
        findings.extend(_receiver_findings(comp))
        findings.extend(_deep_link_findings(comp))
    findings.extend(_flag_findings(manifest))
    findings.extend(apply_bundle(load_builtin(const_manifest_bundle), ws.extracted_dir, manifest))
    return findings
