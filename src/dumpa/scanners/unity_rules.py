"""Unity integration scanner: applies the `unity` rule bundle.

Reports the Unity integration surface (Gaming Services, Firebase config residue,
Addressables presence, non-tracker native plugins) by running the data-driven `unity`
bundle over the extracted tree. Mirrors scanners/engine.py — keeping it a scanner means
it plugs into reporting.build_report and the per-scanner cache exactly like the others.

Runs only behind the Unity gate in scanners/__init__.py (UNITY_SPECS), so it is never
invoked on a non-Unity app.
"""

from __future__ import annotations

from dumpa.core.report import Finding
from dumpa.core.rules import apply_bundle, load_builtin
from dumpa.core.workspace import Workspace

const_unity_bundle = "unity"


def scan(ws: Workspace) -> list[Finding]:
    """Apply the built-in `unity` bundle to extracted/ (no-op if not yet extracted).

    The bundle has no manifest rules, so `apply_bundle` never parses the manifest.
    """
    if not ws.extracted_dir.is_dir():
        return []
    return apply_bundle(load_builtin(const_unity_bundle), ws.extracted_dir)
