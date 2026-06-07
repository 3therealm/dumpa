"""Tracker scanner: privacy/SDK inventory via the trackers rule bundle.

Applies the built-in `trackers` bundle (content matchers over dex/native/manifest plus
manifest-component matchers over the parsed manifest) to the workspace. Each finding
carries the tracker taxonomy (`category`) and SDK owner (`owner`) as attributes, plus
evidence (matched class path / domain, file + byte offset, and/or manifest component).

A single SDK can match on more than one signal (its dex classes *and* its declared
manifest components). Those are merged into one finding per subject so the inventory
counts each SDK once while keeping every piece of evidence.
"""

from __future__ import annotations

from dumpa.core.manifest import load_manifest
from dumpa.core.report import Confidence, Finding
from dumpa.core.rules import apply_bundle, load_builtin
from dumpa.core.workspace import Workspace

const_tracker_bundle = "trackers"

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
    """Detect tracker SDKs by applying the built-in trackers bundle to extracted/."""
    if not ws.extracted_dir.is_dir():
        return []
    findings = apply_bundle(load_builtin(const_tracker_bundle), ws.extracted_dir, load_manifest(ws))
    return _merge_by_subject(findings)
