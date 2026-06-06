"""Environment-variable parsing helpers shared across the toolkit."""

from __future__ import annotations

import os

from dumpa.core.errors import ConfigError


def env_positive_int(name: str, default: int) -> int:
    """Return a positive integer from env, or default when unset."""
    raw = os.environ.get(name, '').strip()
    if not raw:
        return default
    if not raw.isdigit() or int(raw) < 1:
        raise ConfigError(f'{name} must be a positive integer')
    return int(raw)
