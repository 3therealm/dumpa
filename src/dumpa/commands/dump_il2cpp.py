"""`dumpa dump-il2cpp` — dump il2cpp metadata from a Unity APK or a workspace.

With `--workspace`, the dump reads the already-extracted apk from that workspace
(populating it from an .apk first if the workspace is empty) and writes into its
`dumps/` dir — no re-extraction. Without it, a private temp dir is used as before.
"""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.commands.analyze import input_type
from dumpa.convert.pipeline import build_workspace
from dumpa.core.archive import safe_extract_zip
from dumpa.core.config import load_config
from dumpa.core.errors import DumpaError, ToolNotFoundError
from dumpa.core.fs import working_tmp_dir
from dumpa.core.hashing import sha256_file
from dumpa.core.tools import ResolvedTool, ToolRegistry, build_default_registry
from dumpa.core.workspace import Workspace, open_workspace
from dumpa.tools.il2cpp import (
    Il2CppEngine,
    find_il2cpp_inputs,
    get_engine,
    select_inputs,
)

logger = logging.getLogger("dumpa")

const_dump_cs = "dump.cs"


def autodump_workspace(registry: ToolRegistry, ws: Workspace, *, engine_name: str) -> bool:
    """Dump il2cpp into ws.dumps_dir when inputs exist and the tool is available.

    Fail-soft helper for `analyze`'s auto-dump step: returns True if dump.cs is present
    afterward (already dumped or freshly produced), False otherwise. A missing tool or a
    failed dump logs a warning and returns False rather than aborting the analysis.
    """
    if (ws.dumps_dir / const_dump_cs).is_file():
        return True
    if not find_il2cpp_inputs(ws.extracted_dir, None):
        return False  # not an IL2CPP build
    try:
        eng = get_engine(engine_name)
        tool = registry.resolve(eng.tool_name)
    except (ToolNotFoundError, DumpaError):
        logger.warning("auto-dump skipped: il2cpp engine %r unavailable", engine_name)
        return False
    ws.dumps_dir.mkdir(parents=True, exist_ok=True)
    try:
        _run_dump(eng, engine_name, tool, ws.extracted_dir, None, ws.dumps_dir)
    except DumpaError:
        logger.warning("auto-dump failed; continuing without dump.cs", exc_info=True)
        return False
    return (ws.dumps_dir / const_dump_cs).is_file()


def _run_dump(eng: Il2CppEngine, engine_name: str, tool: ResolvedTool,
              extracted: Path, arch: str | None, out: Path) -> None:
    """Find il2cpp inputs under extracted, run the engine, and log the artifacts."""
    candidates = find_il2cpp_inputs(extracted, arch)
    if not candidates:
        detail = f" for arch {arch!r}" if arch else ""
        raise DumpaError(
            f"no il2cpp inputs found{detail} "
            f"(need lib/<abi>/libil2cpp.so + global-metadata.dat)"
        )
    inputs = select_inputs(candidates)
    logger.info("il2cpp: arch=%s binary=%s metadata=%s",
                inputs.arch, inputs.binary.name, inputs.metadata.name)
    result = eng.dump(tool, inputs, out)
    artifacts = ", ".join(sorted(result.artifacts)) or "no named artifacts"
    logger.info("il2cpp dump complete (engine=%s): %s", result.engine, artifacts)
    logger.info("output: %s", out)


def dump_il2cpp(apk_file: Path | None, *, engine: str | None = None,
                arch: str | None = None, out_dir: Path | None = None,
                workspace: Path | None = None) -> None:
    """Dump il2cpp metadata from a Unity APK (or a workspace) into an output directory."""
    config = load_config()
    registry = build_default_registry(config.tool_paths)
    engine_name = engine or config.il2cpp_engine
    eng = get_engine(engine_name)
    tool = registry.resolve(eng.tool_name)  # missing -> ToolNotFoundError -> exit 3

    if workspace is not None:
        with open_workspace(workspace.resolve()) as ws:
            if not ws.is_populated():
                if apk_file is None:
                    raise DumpaError(
                        f"workspace {ws.root} is empty; pass an APK to populate it, "
                        f"or run `dumpa analyze` first"
                    )
                apk_abs = apk_file.resolve()
                if input_type(apk_abs) != "apk":
                    raise DumpaError("dump-il2cpp populates a workspace from an .apk; "
                                     "use `dumpa analyze` for .xapk inputs")
                logger.info("populating workspace from %s", apk_abs.name)
                build_workspace(registry, ws, apk_abs, "apk", sha256_file(apk_abs), None)
            out = out_dir.resolve() if out_dir else ws.dumps_dir
            out.mkdir(parents=True, exist_ok=True)
            _run_dump(eng, engine_name, tool, ws.extracted_dir, arch, out)
        return

    if apk_file is None:
        raise DumpaError("dump-il2cpp needs an APK file argument (or --workspace)")
    apk_abs = apk_file.resolve()
    out = (out_dir or apk_abs.parent / f'{apk_abs.stem}-il2cpp').resolve()

    logger.info("dump-il2cpp: engine=%s apk=%s", engine_name, apk_abs.name)
    with working_tmp_dir(apk_abs.parent) as tmp:
        extracted = tmp / 'extracted'
        safe_extract_zip(apk_abs, extracted)
        _run_dump(eng, engine_name, tool, extracted, arch, out)
