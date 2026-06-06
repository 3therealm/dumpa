"""Scanners: pure `(workspace) -> list[Finding]` functions aggregated into a report.

Every scanner reads a populated workspace's `extracted/` tree and returns Findings
in the shared `core.report` model. `reporting.build_report` runs them all, so adding
a capability (trackers, protections, native, ...) is "register a scanner", never
"add a subsystem". Phase 4 ships engine detection + the Unity deep helper.
"""

from __future__ import annotations

from collections.abc import Callable

from dumpa.core.report import Confidence, Finding
from dumpa.core.workspace import Workspace
from dumpa.scanners import endpoint, engine, native, privacy, protection, tracker, unity

Scanner = Callable[[Workspace], list[Finding]]

# Registration order is the run order; engine detection first so its findings exist
# for primary_engine() and so detail scanners (unity) follow their parent engine.
SCANNERS: tuple[Scanner, ...] = (
    engine.scan, tracker.scan, privacy.scan, protection.scan, native.scan, endpoint.scan,
)

_CONFIDENCE_RANK = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}


def run_all(ws: Workspace) -> list[Finding]:
    """Run every registered scanner over the workspace and concatenate their findings."""
    findings: list[Finding] = []
    for scan in SCANNERS:
        findings.extend(scan(ws))
    if any(f.kind == "engine" and f.subject == "Unity" for f in findings):
        findings.extend(unity.scan(ws))
    return findings


def primary_engine(findings: list[Finding]) -> str | None:
    """Pick the most likely engine: highest-confidence 'engine' finding (bundle order breaks ties)."""
    engines = [f for f in findings if f.kind == "engine"]
    if not engines:
        return None
    return max(engines, key=lambda f: _CONFIDENCE_RANK[f.confidence]).subject
