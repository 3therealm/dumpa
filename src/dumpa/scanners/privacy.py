"""Privacy data-access scanner: which sensitive APIs the code references.

Applies the built-in `privacy` bundle (content matchers over dex/native code) to the
extracted tree. Complements the permission-derived capability report: a permission
says the app *may* access a data class; these findings say the code *references* the
corresponding API (state = "referenced").
"""

from __future__ import annotations

from dumpa.core.report import Finding
from dumpa.core.rules import apply_bundle, load_builtin
from dumpa.core.workspace import Workspace

const_privacy_bundle = "privacy"


def scan(ws: Workspace) -> list[Finding]:
    """Detect references to privacy-sensitive APIs via the built-in privacy bundle."""
    if not ws.extracted_dir.is_dir():
        return []
    return apply_bundle(load_builtin(const_privacy_bundle), ws.extracted_dir)
