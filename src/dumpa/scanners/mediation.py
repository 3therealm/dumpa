"""Mediation-adapter scanner: per-network ad-mediation adapter classes.

Applies the built-in `mediation` bundle (class-path content matchers) to the extracted
tree. Each finding is one mediator->network edge (kind ``mediation-adapter``, carrying
``mediator`` + ``network`` attributes); `core.report.mediation_graph` joins them into a
per-mediator view. Kept a distinct kind from ``tracker`` so adapter hits never inflate the
tracker inventory or density score.
"""

from __future__ import annotations

from dumpa.core.report import Finding
from dumpa.core.rules import apply_bundle, load_builtin
from dumpa.core.workspace import Workspace

const_mediation_bundle = "mediation"


def scan(ws: Workspace) -> list[Finding]:
    """Detect ad-mediation adapter classes via the built-in mediation bundle."""
    if not ws.extracted_dir.is_dir():
        return []
    return apply_bundle(load_builtin(const_mediation_bundle), ws.extracted_dir)
