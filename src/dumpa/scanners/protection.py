"""Protection scanner: packer / anti-debug / integrity inventory.

Applies the built-in `protections` bundle (native-library filename globs + loader /
runtime string markers) to the extracted tree. Reporting only — dumpa inventories
protections, it does not strip or bypass them.
"""

from __future__ import annotations

from dumpa.core.report import Finding
from dumpa.core.rules import apply_bundle, load_builtin
from dumpa.core.workspace import Workspace

const_protection_bundle = "protections"


def scan(ws: Workspace) -> list[Finding]:
    """Detect packers/hardening via the built-in protections bundle."""
    if not ws.extracted_dir.is_dir():
        return []
    return apply_bundle(load_builtin(const_protection_bundle), ws.extracted_dir)
