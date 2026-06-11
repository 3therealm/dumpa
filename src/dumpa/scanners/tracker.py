"""Tracker scanner: privacy/SDK inventory via the trackers rule bundles.

Applies the curated built-in `trackers` bundle plus the imported `trackers-exodus`
bundle (content matchers over dex/native/manifest plus manifest-component matchers over
the parsed manifest) to the workspace. Each finding carries the tracker taxonomy
(`category`) and SDK owner (`owner`) as attributes, plus evidence (matched class path /
domain, file + byte offset, and/or manifest component).

The curated bundle is authoritative: an imported Exodus rule whose signature covers a
class path a curated rule already matches is dropped (class-path containment dedup), so
overlapping SDKs are counted once with the hand-tuned curated metadata.

A single SDK can match on more than one signal (its dex classes *and* its declared
manifest components). Those are merged into one finding per subject so the inventory
counts each SDK once while keeping every piece of evidence.
"""

from __future__ import annotations

import dataclasses
import logging
import re

from dumpa.core.errors import ConfigError
from dumpa.core.manifest import load_manifest
from dumpa.core.report import Confidence, Finding
from dumpa.core.rules import RuleBundle, apply_bundle, load_builtin
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_tracker_bundle = "trackers"
const_imported_bundles = ("trackers_exodus", "trackers_trackercontrol")

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


def _dedup_imported(imported: RuleBundle, curated: RuleBundle) -> RuleBundle:
    """Drop imported subjects whose signature already covers a curated class-path literal.

    Curated rules carry literal class paths in `strings`; if an imported rule's regex matches
    any of them, the two target the same SDK -> curated wins, so every imported rule for that
    subject is removed. APK-independent (computed over rule data), so it does not affect the
    content-hash cache. A broad regex could over-match an unrelated curated literal, which
    only ever favours the authoritative curated rule — acceptable. (Host-only signatures,
    e.g. TrackerControl, never match a class-path literal, so this naturally no-ops there.)
    """
    literals = [s.encode() for r in curated.rules for s in r.strings]
    if not literals:
        return imported
    drop: set[str] = set()
    for rule in imported.rules:
        for pattern in rule.regex:
            try:
                rx = re.compile(pattern.encode())
            except re.error:
                continue
            if any(rx.search(lit) is not None for lit in literals):
                drop.add(rule.subject)
                break
    if not drop:
        return imported
    kept = tuple(r for r in imported.rules if r.subject not in drop)
    return dataclasses.replace(imported, rules=kept)


def scan(ws: Workspace) -> list[Finding]:
    """Detect tracker SDKs by applying the curated + imported trackers bundles."""
    if not ws.extracted_dir.is_dir():
        return []
    manifest = load_manifest(ws)
    curated = load_builtin(const_tracker_bundle)
    findings = apply_bundle(curated, ws.extracted_dir, manifest)
    for name in const_imported_bundles:
        try:
            imported = _dedup_imported(load_builtin(name), curated)
            findings += apply_bundle(imported, ws.extracted_dir, manifest)
        except ConfigError:
            logger.debug("imported bundle %r unavailable; skipping", name, exc_info=True)
    return _merge_by_subject(findings)
