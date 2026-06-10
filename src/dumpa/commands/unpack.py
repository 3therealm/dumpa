"""`dumpa unpack` — extract an APK/XAPK into a reusable workspace, with an apktool decode.

Like `analyze` minus the scanner pass: it lands the canonical `app.apk` + raw
`extracted/` tree, then (by default) runs a full `apktool d` into `smali/` so the app
can be edited and rebuilt losslessly via `dumpa repack`. `.xapk` inputs run the convert
merge first; `.apk` inputs are linked in directly.
"""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.commands.analyze import input_type
from dumpa.convert.pipeline import build_workspace, prepare_convert, workspace_build_options
from dumpa.core.config import load_config
from dumpa.core.hashing import sha256_file
from dumpa.core.tools import build_default_registry
from dumpa.core.workspace import decide_reuse, open_workspace
from dumpa.tools import apktool

logger = logging.getLogger("dumpa")


def unpack(input_file: Path, *, workspace: Path | None = None, force: bool = False,
           decode: bool = True) -> None:
    """Extract input_file into a reusable workspace; decode to smali/ unless decode=False."""
    config = load_config()
    registry = build_default_registry(config.tool_paths)

    input_abs = input_file.resolve()
    in_type = input_type(input_abs)
    if in_type in ("xapk", "apks"):
        prepare_convert(registry, None)  # unpack never signs

    input_sha = sha256_file(input_abs)
    build_options = workspace_build_options(in_type, None)
    ws_path = workspace.resolve() if workspace else Path.cwd() / f'{input_abs.stem}-workspace'

    with open_workspace(ws_path) as ws:
        if decide_reuse(ws, input_sha, force=force, build_options=build_options):
            logger.info("reusing workspace %s (input unchanged)", ws.root)
        else:
            build_workspace(registry, ws, input_abs, in_type, input_sha, None, build_options)
            logger.info("workspace ready")

        if decode and not ws.has_smali():
            logger.info("decode apk -> smali")
            apktool.decode_apk(registry.resolve('apktool'), ws.app_apk, ws.smali_dir)

        logger.info("workspace: %s", ws.root)
        logger.info("  app.apk:   %s", ws.app_apk)
        logger.info("  extracted: %s", ws.extracted_dir)
        if ws.has_smali():
            logger.info("  smali:     %s", ws.smali_dir)
