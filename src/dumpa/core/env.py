"""Environment-variable parsing helpers shared across the toolkit."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

from dumpa.core.errors import ConfigError


def env_positive_int(name: str, default: int) -> int:
    """Return a positive integer from env, or default when unset."""
    raw = os.environ.get(name, '').strip()
    if not raw:
        return default
    if not raw.isdigit() or int(raw) < 1:
        raise ConfigError(f'{name} must be a positive integer')
    return int(raw)


@contextmanager
def temporary_env(overrides: dict[str, str]) -> Iterator[None]:
    """Apply environment overrides for one command path, then restore prior state."""
    previous = {name: os.environ.get(name) for name in overrides}
    try:
        os.environ.update(overrides)
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
