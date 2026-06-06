"""Logging configuration and log-sanitization helpers."""

from __future__ import annotations

import logging
import re
import shlex


def configure_logging(debug: bool = False) -> None:
    """Configure CLI logging once. `debug` raises the level to DEBUG (full tracebacks)."""
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO,
                        format='[%(levelname).1s] %(message)s')


def _sanitize_log_value(value: object) -> str:
    """Remove log-forging control characters from attacker-influenced values."""
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '?', str(value))


def format_command(cmd: list[str]) -> str:
    """Return a shell-like command string for logs without invoking a shell."""
    return ' '.join(shlex.quote(_sanitize_log_value(part)) for part in cmd)
