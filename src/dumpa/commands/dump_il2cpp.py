"""`dumpa dump-il2cpp` — extract a Unity APK and dump its il2cpp metadata."""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.core.archive import _safe_extract_zip
from dumpa.core.config import load_config
from dumpa.core.errors import DumpaError
from dumpa.core.fs import working_tmp_dir
from dumpa.core.tools import build_default_registry
from dumpa.tools.il2cpp import find_il2cpp_inputs, get_engine, select_inputs

logger = logging.getLogger("dumpa")


def dump_il2cpp(apk_file: Path, *, engine: str | None = None,
                arch: str | None = None, out_dir: Path | None = None) -> None:
    """Dump il2cpp metadata from a Unity APK into an output directory."""
    config = load_config()
    registry = build_default_registry(config.tool_paths)
    engine_name = engine or config.il2cpp_engine
    eng = get_engine(engine_name)
    tool = registry.resolve(eng.tool_name)  # missing -> ToolNotFoundError -> exit 3

    apk_abs = apk_file.resolve()
    out = (out_dir or apk_abs.parent / f'{apk_abs.stem}-il2cpp').resolve()

    logger.info("dump-il2cpp: engine=%s apk=%s", engine_name, apk_abs.name)
    with working_tmp_dir(apk_abs.parent) as tmp:
        extracted = tmp / 'extracted'
        _safe_extract_zip(apk_abs, extracted)
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
