"""Secret scanner: hardcoded keys/tokens/credentials via the secrets bundle.

Applies the built-in `secrets` bundle (regex content matchers) to the extracted tree.
Findings include the captured value (capped) as evidence — leads to verify, not
proof: a key may be a test value, third-party, or revoked.
"""

from __future__ import annotations

from dumpa.core.report import Finding
from dumpa.core.rules import apply_bundle, load_builtin
from dumpa.core.workspace import Workspace

const_secrets_bundle = "secrets"


def scan(ws: Workspace) -> list[Finding]:
    """Detect hardcoded secrets via the built-in secrets bundle."""
    if not ws.extracted_dir.is_dir():
        return []
    return apply_bundle(load_builtin(const_secrets_bundle), ws.extracted_dir)
