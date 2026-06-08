"""`dumpa repack` — rebuild a workspace's decoded smali tree into an installable apk.

Operates on the `smali/` tree produced by `dumpa unpack --decode`, never the original
input, so edits are reversible: `apktool b` -> zipalign -> optional re-sign (Phase 1
signing presets). Re-signing a modified app is opt-in via `--signing`.
"""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.convert.build import pack_align_sign
from dumpa.core.config import load_config
from dumpa.core.errors import DumpaError
from dumpa.core.tools import build_default_registry
from dumpa.core.workspace import Workspace
from dumpa.signing import resolve_signing

logger = logging.getLogger("dumpa")


def repack(workspace_dir: Path, *, signing: str | None = None, out: Path | None = None) -> None:
    """Repack a workspace's smali/ tree into an apk at `out` (default <name>-repacked.apk)."""
    ws = Workspace(root=workspace_dir.resolve())
    if ws.read_meta() is None:
        raise DumpaError(
            f"{ws.root} is not a dumpa workspace; run `dumpa unpack` first")
    if not ws.has_smali():
        raise DumpaError(
            f"{ws.root} has no decoded smali tree; run `dumpa unpack --decode` first")

    config = load_config()
    registry = build_default_registry(config.tool_paths)
    sign_config = resolve_signing(signing, config, registry)

    required = ('apktool', 'zipalign', 'apksigner') if sign_config else ('apktool', 'zipalign')
    registry.require(*required)

    out_path = out.resolve() if out else Path.cwd() / f'{ws.root.name}-repacked.apk'
    pack_align_sign(registry, ws.smali_dir, out_path, sign_config)
    logger.info("repacked apk: %s", out_path)
