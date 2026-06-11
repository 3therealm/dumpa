"""Data Safety comparison: observed data collection vs the developer's Play disclosure.

The privacy-report capstone. Joins what dumpa *observed* (tracker / capability /
data-access findings) against what the app *declared* in its Play Data Safety form, and
emits a `data-safety-gap` finding for each observed category that the disclosure does
*not* cover — the actionable "undisclosed collection" signal. One informational
`data-safety` finding records the declared set for context.

Scope is gaps-only: we never flag disclosed-but-unobserved, because a static scan
missing a signal is not proof the app omits it (that direction is all false positives).

The fetch is split from the comparison: `resolve_disclosure` is the networked, opt-in,
sidecar-memoized lookup (mirrors `core.gametype.resolve_game_types`); `compare` is a
pure function over (disclosure, findings) so it is trivially unit-tested. The
category->label join is data (`dumpa/data/datasafety_map.toml`).
"""

from __future__ import annotations

import importlib.resources
import json
import logging
import tomllib
from typing import Any, cast

from dumpa.core.datasafety import DataSafetyDisclosure, fetch_datasafety
from dumpa.core.manifest import load_manifest
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_data_package = "dumpa.data"
const_map_resource = "datasafety_map.toml"
const_disclosure_kind = "data-safety"
const_gap_kind = "data-safety-gap"

# Finding kinds whose `category` attribute represents observed data collection.
_OBSERVED_KINDS = ("tracker", "capability", "data-access")

# Ranks so a gap inherits the strongest evidence among its contributing findings.
_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
_STATE_RANK = {
    FindingState.PRESENT: 0, FindingState.REFERENCED: 1,
    FindingState.INITIALIZED: 2, FindingState.NETWORK_OBSERVED: 3,
}


def _load_category_map() -> dict[str, tuple[str, ...]]:
    """Load the observed-category -> Data Safety label(s) table."""
    resource = importlib.resources.files(const_data_package) / const_map_resource
    with resource.open("rb") as f:
        data = tomllib.load(f)
    raw = data.get("map", {})
    if not isinstance(raw, dict):
        return {}
    out: dict[str, tuple[str, ...]] = {}
    for category, labels in cast("dict[str, Any]", raw).items():
        if isinstance(labels, list):
            out[str(category)] = tuple(str(label) for label in labels)
    return out


# ----- fetch (networked, opt-in, memoized) ----------------------------------------

def _read_sidecar(ws: Workspace) -> tuple[bool, DataSafetyDisclosure | None]:
    """Read the memoized disclosure. Returns (resolved, disclosure).

    An empty object ({}) means "looked up once, none found" — distinct from a missing
    file (not yet looked up), so the lookup happens at most once per workspace.
    """
    path = ws.datasafety_sidecar
    if not path.is_file():
        return (False, None)
    try:
        data = json.loads(path.read_text(encoding="UTF-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return (False, None)
    if not isinstance(data, dict):
        return (False, None)
    if not data:
        return (True, None)
    try:
        return (True, DataSafetyDisclosure.from_dict(cast("dict[str, Any]", data)))
    except (KeyError, TypeError, ValueError):
        return (False, None)


def _write_sidecar(ws: Workspace, disclosure: DataSafetyDisclosure | None) -> None:
    path = ws.datasafety_sidecar
    payload = disclosure.to_dict() if disclosure is not None else {}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="UTF-8")
    except OSError:
        logger.debug("datasafety: cannot write sidecar %s", path, exc_info=True)


def resolve_disclosure(ws: Workspace, *, allow_network: bool, timeout: int,
                       ttl_days: int) -> DataSafetyDisclosure | None:
    """Resolve the workspace's Data Safety disclosure, memoized in dumps/datasafety.json.

    Sidecar hit returns immediately. Otherwise read the package from the manifest, fetch
    (cache-or-network per `allow_network`), and write the sidecar (even when absent, so
    the lookup happens once per workspace).
    """
    resolved, cached = _read_sidecar(ws)
    if resolved:
        return cached
    manifest = load_manifest(ws)
    package = manifest.package if manifest else None
    disclosure: DataSafetyDisclosure | None = None
    if package:
        disclosure = fetch_datasafety(package, cache_dir=ws.datasafety_cache_dir,
                                      allow_network=allow_network, timeout=timeout,
                                      ttl_days=ttl_days)
    _write_sidecar(ws, disclosure)
    return disclosure


# ----- comparison (pure) ----------------------------------------------------------

def compare(disclosure: DataSafetyDisclosure, findings: list[Finding]) -> list[Finding]:
    """Compare observed categories against the disclosure; emit data-safety findings.

    Returns one informational `data-safety` finding (the declared set) plus a
    `data-safety-gap` finding for every observed, *comparable* category whose covering
    Data Safety label(s) are absent from the disclosure. A category is comparable only
    if it appears in datasafety_map.toml (categories with no Data Safety equivalent are
    excluded by design, never flagged).
    """
    cat_map = _load_category_map()
    disclosed = disclosure.labels()

    # Group contributing findings per observed category.
    contributors: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.kind not in _OBSERVED_KINDS:
            continue
        category = finding.attributes.get("category")
        if not category or category not in cat_map:
            continue
        contributors.setdefault(category, []).append(finding)

    out: list[Finding] = [_disclosure_finding(disclosure)]
    for category in sorted(contributors):
        covering = cat_map[category]
        if any(label in disclosed for label in covering):
            continue  # disclosed -> not a gap
        out.append(_gap_finding(category, covering, contributors[category], disclosure))
    return out


def _disclosure_finding(disclosure: DataSafetyDisclosure) -> Finding:
    return Finding(
        kind=const_disclosure_kind,
        subject="declared data types",
        confidence=Confidence.LOW,
        state=FindingState.PRESENT,
        attributes={
            "collected": ", ".join(disclosure.collected),
            "shared": ", ".join(disclosure.shared),
        },
        evidence=[Evidence(
            description=f"Google Play Data Safety disclosure; fetched {disclosure.fetched}",
            snippet=disclosure.url, tool="playstore")],
        locations=[Location(domain="play.google.com")],
    )


def _gap_finding(category: str, covering: tuple[str, ...], contributors: list[Finding],
                 disclosure: DataSafetyDisclosure) -> Finding:
    subjects = sorted({c.subject for c in contributors})
    confidence = max((c.confidence for c in contributors),
                     key=lambda x: _CONFIDENCE_RANK[x])
    state = max((c.state for c in contributors), key=lambda x: _STATE_RANK[x])
    return Finding(
        kind=const_gap_kind,
        subject=category,
        confidence=confidence,
        state=state,
        attributes={
            "category": category,
            "covering_labels": ", ".join(covering),
            "observed_in": ", ".join(subjects),
        },
        evidence=[Evidence(
            description=(f"observed {category} ({', '.join(subjects)}) but the Data Safety "
                         f"form does not declare {' / '.join(covering)}; "
                         f"fetched {disclosure.fetched}"),
            snippet=disclosure.url, tool="playstore")],
        locations=[Location(domain="play.google.com")],
    )
