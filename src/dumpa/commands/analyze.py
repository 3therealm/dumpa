"""`dumpa analyze` — extract an APK/XAPK once into a reusable workspace.

The umbrella command: it lands a single canonical apk plus its raw extraction in one
reproducible directory so later commands (dump-il2cpp, future scanners) never
re-extract the input. `.xapk` inputs run the convert merge pipeline first; `.apk`
inputs are linked in directly.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from dumpa.convert.pipeline import build_workspace, prepare_convert, workspace_build_options
from dumpa.convert.validate import report_output_apk
from dumpa.core.config import (
    Config,
    const_default_validation_timeout,
    const_env_native_r2_all_abis,
    const_env_play_lookup,
    const_env_validation_timeout,
    load_config,
)
from dumpa.core.env import env_positive_int, temporary_env
from dumpa.core.errors import DumpaError, ToolNotFoundError
from dumpa.core.hashing import sha256_file
from dumpa.core.report import Report, write_json
from dumpa.core.tools import ToolRegistry, build_default_registry
from dumpa.core.workspace import Workspace, decide_reuse, open_workspace
from dumpa.reporting import build_report
from dumpa.signing import resolve_signing
from dumpa.tools import aapt

logger = logging.getLogger("dumpa")

const_ext_apk = ".apk"
const_ext_xapk = ".xapk"
const_ext_apks = ".apks"
const_file_report_json = "report.json"
const_optional_native_r2 = "native_r2"

# Input types whose canonical app.apk is produced by the merge/build pipeline
# (vs. an .apk, which is copied in directly).
const_build_input_types = ("xapk", "apks")


def input_type(path: Path) -> str:
    """Classify an input path as 'apk', 'xapk', or 'apks' by suffix; raise otherwise."""
    suffix = path.suffix.lower()
    if suffix == const_ext_xapk:
        return "xapk"
    if suffix == const_ext_apks:
        return "apks"
    if suffix == const_ext_apk:
        return "apk"
    raise DumpaError(f"unsupported input {path.name}: expected a .apk, .xapk, or .apks file")


def _validation_timeout() -> int:
    return env_positive_int(const_env_validation_timeout, const_default_validation_timeout)


def _package_of(registry: ToolRegistry, apk: Path) -> str | None:
    """Read the package name from an apk via aapt; None if aapt is unavailable."""
    try:
        tool = registry.resolve('aapt')
    except ToolNotFoundError:
        return None
    return aapt.read_badging(tool, apk, _validation_timeout()).package


def _report_workspace(registry: ToolRegistry, ws: Workspace, *,
                      signed_expected: bool, input_size: int, use_cache: bool = True,
                      extra: tuple[str, ...] | None = None) -> None:
    """Log a one-line apk sanity report, write the JSON report, and point at the layout."""
    package = _package_of(registry, ws.app_apk) or '?'
    report_output_apk(registry, ws.app_apk, package, signed_expected, input_size)
    report_path = ws.reports_dir / const_file_report_json
    write_json(build_report(registry, ws, use_cache=use_cache, extra=extra), report_path)
    logger.info("workspace: %s", ws.root)
    logger.info("  extracted: %s", ws.extracted_dir)
    logger.info("  dumps:     %s", ws.dumps_dir)
    logger.info("  report:    %s", report_path)


@contextmanager
def open_for_diff(input_path: Path) -> Iterator[tuple[Workspace, Report]]:
    """Yield a populated workspace + its report, keeping the workspace open.

    Shared by `diff`: a directory is treated as an existing dumpa workspace; an apk/xapk
    is extracted into a throwaway workspace that stays open for the block's duration, so
    workspace sidecars (`dumps/native/*.json`, `dumps/dump.cs`) written by `build_report`
    are readable for the symbol/method diffs. apk/xapk inputs are reported unsigned (a diff
    read never re-signs).
    """
    config = load_config()
    registry = build_default_registry(config.tool_paths)
    input_abs = input_path.resolve()

    if input_abs.is_dir():
        ws = Workspace(root=input_abs)
        if ws.read_meta() is None:
            raise DumpaError(f"{input_abs} is not a dumpa workspace; pass an .apk/.xapk/.apks or run analyze first")
        yield ws, build_report(registry, ws)
        return

    in_type = input_type(input_abs)
    if in_type in const_build_input_types:
        prepare_convert(registry, None)
    with open_workspace(None) as ws:
        build_workspace(registry, ws, input_abs, in_type, sha256_file(input_abs), None)
        yield ws, build_report(registry, ws)


def report_for_input(input_path: Path) -> Report:
    """Build a Report for an apk/xapk (ephemeral workspace) or an existing workspace dir.

    Shared by `load`: an apk/xapk is extracted into a throwaway workspace and reported
    unsigned; a directory is treated as an existing dumpa workspace.
    """
    with open_for_diff(input_path) as (_ws, report):
        return report


def _maybe_autodump(registry: ToolRegistry, ws: Workspace, config: Config, *, enabled: bool) -> None:
    """Auto-dump il2cpp into the workspace when enabled (so the dumpcs scanner has input)."""
    if not enabled:
        return
    # Lazy import: dump_il2cpp imports analyze at module load, so this breaks the cycle.
    from dumpa.commands.dump_il2cpp import autodump_workspace
    autodump_workspace(registry, ws, engine_name=config.il2cpp_engine)


def _maybe_decompile(ws_path: Path, *, enabled: bool) -> None:
    """Run a full JADX decompile into the workspace when --jadx was passed (opt-in, heavy)."""
    if not enabled:
        return
    # Lazy import: decompile imports analyze at module load, so this breaks the cycle.
    from dumpa.commands.decompile import decompile as run_decompile
    run_decompile(None, all_classes=True, workspace=ws_path)


def _maybe_xref(ws: Workspace, *, enabled: bool) -> None:
    """Build dumps/xref.json from the just-written report and log the correlation count."""
    if not enabled:
        return
    import datetime

    from dumpa.core.report import read_json
    from dumpa.core.xref import build_xref, write_xref
    report = read_json(ws.reports_dir / const_file_report_json)
    if report is None:
        return
    meta = ws.read_meta()
    sha = meta.input_sha256 if meta is not None else ""
    built = datetime.datetime.now(datetime.UTC).isoformat()
    index = build_xref(ws, list(report.findings), input_sha256=sha, built=built)
    write_xref(index, ws.xref_sidecar)
    multi = sum(1 for e in index.entities if len(e.layers) >= 2)
    logger.info("  xref:      %d cross-layer correlations (%s)", multi, ws.xref_sidecar)


def _merge_optional_scanners(ws: Workspace, requested: tuple[str, ...]) -> None:
    """Persist newly requested optional scanners into workspace metadata."""
    if not requested:
        return
    meta = ws.read_meta()
    if meta is None:
        return
    merged = tuple(dict.fromkeys((*meta.optional_scanners, *requested)))
    if merged == meta.optional_scanners:
        return
    ws.write_meta(replace(meta, optional_scanners=merged))


def analyze(input_file: Path, *, workspace: Path | None = None, force: bool = False,
            signing: str | None = None, use_cache: bool = True,
            no_dump: bool = False, no_network: bool = False, jadx: bool = False,
            xref: bool = False, r2: bool = False, all_abis: bool = False) -> None:
    """Extract input_file into a reproducible workspace, reusing it when unchanged."""
    env = {}
    if no_network:
        env[const_env_play_lookup] = "0"  # scanners read play_lookup from config/env
    if r2 and all_abis:
        env[const_env_native_r2_all_abis] = "1"  # native_r2 reads this from config/env
    with temporary_env(env):
        config = load_config()
        registry = build_default_registry(config.tool_paths)
        sign_config = resolve_signing(signing, config, registry)
        autodump_enabled = config.analysis.auto_dump and not no_dump

        input_abs = input_file.resolve()
        in_type = input_type(input_abs)
        if in_type in const_build_input_types:
            prepare_convert(registry, sign_config)

        requested_optional = (const_optional_native_r2,) if r2 else ()
        input_sha = sha256_file(input_abs)
        build_options = workspace_build_options(in_type, sign_config)
        signed_expected = in_type in const_build_input_types and sign_config is not None
        ws_path = workspace.resolve() if workspace else Path.cwd() / f'{input_abs.stem}-workspace'

        with open_workspace(ws_path) as ws:
            if decide_reuse(ws, input_sha, force=force, build_options=build_options):
                logger.info("reusing workspace %s (input unchanged)", ws.root)
                meta = ws.read_meta()
                size = meta.input_size if meta else input_abs.stat().st_size
                _merge_optional_scanners(ws, requested_optional)
                _maybe_autodump(registry, ws, config, enabled=autodump_enabled)
                _report_workspace(registry, ws, signed_expected=signed_expected, input_size=size,
                                  use_cache=use_cache)
            else:
                build_workspace(registry, ws, input_abs, in_type, input_sha, sign_config,
                                build_options, optional_scanners=requested_optional)
                logger.info("workspace ready")
                _maybe_autodump(registry, ws, config, enabled=autodump_enabled)
                _report_workspace(registry, ws, signed_expected=signed_expected,
                                  input_size=input_abs.stat().st_size, use_cache=use_cache)
            _maybe_xref(ws, enabled=xref)
            decompile_ws = ws.root

        _maybe_decompile(decompile_ws, enabled=jadx)
