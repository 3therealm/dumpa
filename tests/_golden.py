"""Stable projection of a Report for golden-sample corpus regression.

A `Report` carries plenty of run-, tool-, and file-position-dependent detail
(timestamps, tool versions, byte offsets, RVAs, snippets) that legitimately
varies across machines and apktool versions. Pinning the whole report would
churn on noise. `project()` keeps only the signals a rule/parser change should be
caught by — engine identity, the tracker/protection/secret/capability subjects,
their confidence and state, and the cheap manifest facts — in a deterministic,
machine-independent shape.

Excluded on purpose: `created`, `tool_versions`, `signer_*` (needs apksigner),
input_size, per-finding evidence/locations/attributes/offsets/RVAs, and the
network-derived Data Safety findings (the harness runs with DUMPA_PLAY_LOOKUP=0,
but excluding them keeps the projection robust even if that ever changes).
"""

from __future__ import annotations

from typing import Any

from dumpa.core.report import Report

# Findings whose presence depends on a network lookup; never part of the snapshot.
_NETWORK_KINDS = frozenset({"data-safety", "data-safety-gap"})


def project(report: Report) -> dict[str, Any]:
    """Reduce a Report to a deterministic, tool-/machine-independent dict."""
    f = report.facts
    facts = {
        "input_sha256": f.input_sha256,
        "package": f.package,
        "version_name": f.version_name,
        "engine": f.engine,
        "game_types": sorted(f.game_types),
        "abis": sorted(f.abis),
        "permissions": sorted(f.permissions),
        "exported_component_count": f.exported_component_count,
    }

    by_kind: dict[str, set[tuple[str, str, str]]] = {}
    for finding in report.findings:
        if finding.kind in _NETWORK_KINDS:
            continue
        triple = (finding.subject, finding.confidence.value, finding.state.value)
        by_kind.setdefault(finding.kind, set()).add(triple)
    findings = {
        kind: [list(t) for t in sorted(triples)]
        for kind, triples in sorted(by_kind.items())
    }

    return {"facts": facts, "findings": findings}
