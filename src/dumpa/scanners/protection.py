"""Protection scanner: packer / anti-debug / integrity inventory.

Applies the curated built-in `protections` bundle (native-library filename globs + loader /
runtime string markers) plus the imported `protections-apkid` bundle (APKiD-derived
packer/protector/obfuscator signatures) to the extracted tree. Reporting only — dumpa
inventories protections, it does not strip or bypass them.

The curated bundle is authoritative: an imported rule whose subject a curated rule already
covers is dropped. Imported rules that split a single APKiD rule across matcher kinds are
collapsed back into one finding per subject.
"""

from __future__ import annotations

import dataclasses
import logging

from dumpa.core.errors import ConfigError
from dumpa.core.report import Confidence, Finding
from dumpa.core.rules import apply_bundle, load_builtin
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_protection_bundle = "protections"
const_imported_bundles = ("protections_apkid",)

_CONFIDENCE_RANK = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}


def _merge_by_subject(findings: list[Finding]) -> list[Finding]:
    """Collapse findings sharing a subject into one, unioning evidence + locations."""
    merged: dict[str, Finding] = {}
    order: list[str] = []
    for f in findings:
        cur = merged.get(f.subject)
        if cur is None:
            merged[f.subject] = f
            order.append(f.subject)
            continue
        stronger = cur if _CONFIDENCE_RANK[cur.confidence] >= _CONFIDENCE_RANK[f.confidence] else f
        merged[f.subject] = Finding(
            kind=cur.kind,
            subject=cur.subject,
            confidence=stronger.confidence,
            state=cur.state,
            attributes={**f.attributes, **cur.attributes},
            evidence=cur.evidence + f.evidence,
            locations=cur.locations + f.locations,
        )
    return [merged[s] for s in order]


def scan(ws: Workspace) -> list[Finding]:
    """Detect packers/hardening via the curated + imported protections bundles."""
    if not ws.extracted_dir.is_dir():
        return []
    curated = load_builtin(const_protection_bundle)
    curated_subjects = {r.subject for r in curated.rules}
    findings = apply_bundle(curated, ws.extracted_dir)
    for name in const_imported_bundles:
        try:
            imported = load_builtin(name)
        except ConfigError:
            logger.debug("imported bundle %r unavailable; skipping", name, exc_info=True)
            continue
        kept = tuple(r for r in imported.rules if r.subject not in curated_subjects)
        if kept:
            findings += apply_bundle(dataclasses.replace(imported, rules=kept), ws.extracted_dir)
    return _merge_by_subject(findings)
