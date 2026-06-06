"""Engine scanner: data-driven game-engine detection over a workspace.

Thin wrapper that applies the built-in `engines` rule bundle (Phase 3) to the
workspace's extracted tree. Keeping it a scanner means engine detection plugs into
`reporting.build_report` exactly like the tracker/protection scanners will later.
"""

from __future__ import annotations

from dumpa.core.report import Finding
from dumpa.core.rules import apply_bundle, load_builtin
from dumpa.core.workspace import Workspace

const_engine_bundle = "engines"


def scan(ws: Workspace) -> list[Finding]:
    """Detect game engines by applying the built-in engines bundle to extracted/."""
    if not ws.extracted_dir.is_dir():
        return []
    return apply_bundle(load_builtin(const_engine_bundle), ws.extracted_dir)
