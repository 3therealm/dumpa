"""Shared command dispatch: map toolkit exceptions to stable process exit codes.

Commands raise; they never call sys.exit. run_command() is the single place that
translates a failure into an exit code (see docs/architecture.md section 9).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from zipfile import BadZipFile

from dumpa.core.errors import (
    ConfigError,
    DumpaError,
    ManifestError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
    UnsafeArchiveError,
)

logger = logging.getLogger("dumpa")

# Order matters: a subclass (ToolTimeoutError) must precede its base (ToolExecutionError).
_EXIT_CODES: tuple[tuple[type[DumpaError], int], ...] = (
    (ToolNotFoundError, 3),
    (ToolTimeoutError, 4),
    (ToolExecutionError, 5),
    (UnsafeArchiveError, 6),
    (ManifestError, 7),
    (ConfigError, 8),
)


def run_command(fn: Callable[[], None]) -> None:
    """Run fn, mapping known failures to documented exit codes; unexpected errors -> exit 2."""
    try:
        fn()
    except SystemExit:
        raise
    except DumpaError as e:
        logger.error("%s", e)
        logger.debug("command failed", exc_info=True)
        for typ, code in _EXIT_CODES:
            if isinstance(e, typ):
                raise SystemExit(code) from e
        raise SystemExit(1) from e
    except (BadZipFile, OSError) as e:
        logger.error("%s", e)
        logger.debug("command failed", exc_info=True)
        raise SystemExit(1) from e
    except Exception as e:
        logger.error("unexpected error: %s", e)
        logger.debug("unexpected failure", exc_info=True)
        raise SystemExit(2) from e
