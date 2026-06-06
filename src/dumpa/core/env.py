"""Environment-variable parsing helpers shared across the toolkit."""

from __future__ import annotations

import os


def _env_positive_int(name: str, default: int) -> int:
    """Return a positive integer from env, or default when unset."""
    raw = os.environ.get(name, '').strip()
    if not raw:
        return default
    if not raw.isdigit() or int(raw) < 1:
        raise SystemExit(f'{name} must be a positive integer')
    return int(raw)
