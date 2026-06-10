"""Shared command dispatch: map toolkit exceptions to stable process exit codes.

Commands raise; they never call sys.exit. run_command() is the single place that
translates a failure into an exit code (see docs/architecture.md section 9).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
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
from dumpa.core.tools import ToolRegistry
from dumpa.core.workspace import Workspace

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


@contextmanager
def open_target(registry: ToolRegistry, target: Path) -> Iterator[Workspace]:
    """Yield a populated workspace for a workspace dir or an .apk/.xapk input.

    Shared by the analysis-only scan commands (scan-native, scan-trackers,
    scan-protections): a workspace directory is used in place; an .apk/.xapk is
    extracted once into a throwaway workspace via the convert pipeline (reusing
    build_workspace + decide_reuse). Imports are local to avoid a base<->analyze
    import cycle (analyze imports the report stack, not the other way round).
    """
    from dumpa.commands.analyze import input_type
    from dumpa.convert.pipeline import build_workspace, prepare_convert
    from dumpa.core.hashing import sha256_file
    from dumpa.core.workspace import open_workspace

    target_abs = target.resolve()
    if target_abs.is_dir():
        ws = Workspace(root=target_abs)
        if ws.read_meta() is None:
            raise DumpaError(f"{target_abs} is not a dumpa workspace; "
                             f"pass an .apk/.xapk or run analyze first")
        yield ws
        return

    in_type = input_type(target_abs)
    if in_type == "xapk":
        prepare_convert(registry, None)
    with open_workspace(None) as ws:
        build_workspace(registry, ws, target_abs, in_type, sha256_file(target_abs), None)
        yield ws


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
