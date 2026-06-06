"""`dumpa clean` — remove a workspace directory safely."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from dumpa.core.errors import DumpaError
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")


def clean(workspace: Path) -> None:
    """Delete a dumpa workspace directory (refuses anything without a workspace.json marker)."""
    root = workspace.resolve()
    if not root.is_dir():
        raise DumpaError(f"not a directory: {root}")
    ws = Workspace(root=root)
    if ws.read_meta() is None:
        raise DumpaError(
            f"refusing to remove {root}: not a dumpa workspace (no workspace.json marker)"
        )
    shutil.rmtree(root)
    logger.info("removed workspace %s", root)
