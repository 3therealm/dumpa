"""`dumpa decompile` — read-only JADX Java/Kotlin decompilation.

A read-only viewer for human-readable code. Output is a workspace *artifact*, never a
scanner finding, so it does not touch the per-scanner cache; provenance lives in a
sidecar (`<out>/.dumpa-decompile.json`) instead.

On-demand by design: it requires a selector so a casual run never decompiles a whole
multi-hundred-MB game by accident. `--class a.b.C` is the cheap path (jadx
`--single-class`); `--all` is the explicit, heavy full-APK escape hatch. (jadx has no
native package-include filter, so a `--package` selector is intentionally not offered —
use `--class` for a single type or `--all` for everything.)

jadx is optional (`required=False`): when it is not installed the command logs a warning
and returns cleanly rather than failing.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from dumpa.commands.analyze import input_type
from dumpa.convert.pipeline import build_workspace
from dumpa.core.config import load_config
from dumpa.core.errors import DumpaError, ToolNotFoundError
from dumpa.core.fs import create_or_recreate_dir
from dumpa.core.hashing import sha256_file
from dumpa.core.process import run
from dumpa.core.tools import ResolvedTool, ToolRegistry, build_default_registry
from dumpa.core.workspace import Workspace, open_workspace

logger = logging.getLogger("dumpa")

const_jadx_tool = "jadx"
const_sidecar = ".dumpa-decompile.json"


def _sidecar_matches(out: Path, want: dict[str, str]) -> bool:
    """True when a prior decompile in `out` used the same tool version, selector, and input."""
    path = out / const_sidecar
    if not path.is_file():
        return False
    try:
        prev = json.loads(path.read_text(encoding="UTF-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return False
    return isinstance(prev, dict) and all(prev.get(k) == v for k, v in want.items())


def _write_sidecar(out: Path, meta: dict[str, str]) -> None:
    (out / const_sidecar).write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n",
                                     encoding="UTF-8")


def _run_jadx(tool: ResolvedTool, apk: Path, out: Path, target_class: str | None) -> None:
    args = ["-d", str(out)]
    if target_class is not None:
        args += ["--single-class", target_class]
    args.append(str(apk))
    run(tool.argv(*args), fail_msg="jadx decompilation failed")


def decompile(apk_file: Path | None, *, target_class: str | None = None, all_classes: bool = False,
              out_dir: Path | None = None, workspace: Path | None = None) -> None:
    """Decompile an APK (or a workspace's app.apk) with jadx into a read-only output dir."""
    if bool(target_class) == all_classes:
        raise DumpaError("decompile needs exactly one selector: --class <name> or --all")

    config = load_config()
    registry = build_default_registry(config.tool_paths)
    try:
        tool = registry.resolve(const_jadx_tool)
    except ToolNotFoundError:
        logger.warning("jadx not found; skipping decompilation (install jadx to enable it)")
        return

    selector = target_class if target_class is not None else "*all*"

    def _do(apk: Path, out: Path) -> None:
        want = {"tool": "jadx", "version": tool.version or "?",
                "selector": selector, "input_sha256": sha256_file(apk)}
        if _sidecar_matches(out, want):
            logger.info("decompile up to date: %s", out)
            return
        if (out / const_sidecar).is_file():
            create_or_recreate_dir(out)
        else:
            out.mkdir(parents=True, exist_ok=True)
        logger.info("decompiling (%s) -> %s", selector, out)
        _run_jadx(tool, apk, out, target_class)
        _write_sidecar(out, want)
        logger.info("decompile complete: %s", out)

    if workspace is not None:
        with open_workspace(workspace.resolve()) as ws:
            apk = _resolve_workspace_apk(registry, apk_file, ws)
            _do(apk, out_dir.resolve() if out_dir else ws.decompiled_dir)
        return

    if apk_file is None:
        raise DumpaError("decompile needs an APK file argument (or --workspace)")
    apk = apk_file.resolve()
    if input_type(apk) != "apk":
        raise DumpaError("decompile reads an .apk directly; use --workspace for an analyzed .xapk")
    _do(apk, out_dir.resolve() if out_dir else apk.parent / f"{apk.stem}-decompiled")


def _resolve_workspace_apk(registry: ToolRegistry, apk_file: Path | None, ws: Workspace) -> Path:
    """The app.apk of a workspace, populating it from a passed .apk if it is empty."""
    if not ws.is_populated():
        if apk_file is None:
            raise DumpaError(
                f"workspace {ws.root} is empty; pass an APK to populate it, "
                f"or run `dumpa analyze` first")
        apk_abs = apk_file.resolve()
        if input_type(apk_abs) != "apk":
            raise DumpaError("decompile populates a workspace from an .apk; "
                             "use `dumpa analyze` for .xapk inputs")
        logger.info("populating workspace from %s", apk_abs.name)
        build_workspace(registry, ws, apk_abs, "apk", sha256_file(apk_abs), None)
    return ws.app_apk
