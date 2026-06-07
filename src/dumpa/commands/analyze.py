"""`dumpa analyze` — extract an APK/XAPK once into a reusable workspace.

The umbrella command: it lands a single canonical apk plus its raw extraction in one
reproducible directory so later commands (dump-il2cpp, future scanners) never
re-extract the input. `.xapk` inputs run the convert merge pipeline first; `.apk`
inputs are linked in directly.
"""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.convert.pipeline import build_merged_apk, prepare_convert
from dumpa.convert.validate import report_output_apk
from dumpa.core.archive import safe_extract_zip
from dumpa.core.config import (
    SigningConfig,
    const_default_validation_timeout,
    const_env_validation_timeout,
    load_config,
)
from dumpa.core.env import env_positive_int
from dumpa.core.errors import DumpaError, ToolNotFoundError
from dumpa.core.fs import link_or_copy, working_tmp_dir
from dumpa.core.hashing import sha256_file
from dumpa.core.report import Report, write_json
from dumpa.core.tools import ToolRegistry, build_default_registry
from dumpa.core.workspace import Workspace, decide_reuse, make_meta, open_workspace
from dumpa.reporting import build_report
from dumpa.signing import resolve_signing
from dumpa.tools import aapt

logger = logging.getLogger("dumpa")

const_ext_apk = ".apk"
const_ext_xapk = ".xapk"
const_file_report_json = "report.json"


def input_type(path: Path) -> str:
    """Classify an input path as 'apk' or 'xapk' by suffix; raise otherwise."""
    suffix = path.suffix.lower()
    if suffix == const_ext_xapk:
        return "xapk"
    if suffix == const_ext_apk:
        return "apk"
    raise DumpaError(f"unsupported input {path.name}: expected a .apk or .xapk file")


def collect_tool_versions(registry: ToolRegistry, names: list[str]) -> dict[str, str]:
    """Resolve each named tool and record its version where known (for the workspace marker)."""
    out: dict[str, str] = {}
    for name in names:
        try:
            tool = registry.resolve(name)
        except ToolNotFoundError:
            continue
        if tool.version:
            out[name] = tool.version
    return out


def _validation_timeout() -> int:
    return env_positive_int(const_env_validation_timeout, const_default_validation_timeout)


def _workspace_build_options(in_type: str, sign_config: SigningConfig | None) -> dict[str, str] | None:
    """Return the build options that affect reusable workspace output."""
    if in_type != "xapk":
        return None
    if sign_config is None:
        return {"xapk_signing": "unsigned"}
    return {
        "xapk_signing": "signed",
        "keystore_file": str(sign_config.keystore_file.resolve()),
        "keystore_sha256": sha256_file(sign_config.keystore_file),
        "key_alias": sign_config.key_alias,
        "min_sdk_version": str(sign_config.min_sdk_version or ""),
    }


def _package_of(registry: ToolRegistry, apk: Path) -> str | None:
    """Read the package name from an apk via aapt; None if aapt is unavailable."""
    try:
        tool = registry.resolve('aapt')
    except ToolNotFoundError:
        return None
    return aapt.read_badging(tool, apk, _validation_timeout()).package


def build_workspace(registry: ToolRegistry, ws: Workspace, input_abs: Path,
                    in_type: str, input_sha256: str, sign_config: SigningConfig | None,
                    build_options: dict[str, str] | None = None) -> None:
    """Populate a fresh workspace: produce app.apk, extract it, and write the marker."""
    ws.prepare_build()
    if in_type == "xapk":
        # Build merge scratch under the workspace root (same FS -> instant rename of the
        # result), then free it before extracting app.apk to keep peak disk bounded.
        with working_tmp_dir(ws.root) as scratch:
            target, _package = build_merged_apk(registry, scratch, input_abs, sign_config)
            target.replace(ws.app_apk)
        tool_names = ['apktool', 'zipalign', 'aapt']
        if sign_config is not None:
            tool_names.append('apksigner')
    else:
        link_or_copy(input_abs, ws.app_apk)
        tool_names = ['aapt']

    safe_extract_zip(ws.app_apk, ws.extracted_dir)
    ws.write_meta(make_meta(
        input_path=input_abs,
        input_sha256=input_sha256,
        input_size=input_abs.stat().st_size,
        input_type=in_type,
        tool_versions=collect_tool_versions(registry, tool_names),
        build_options=build_options,
    ))


def _report_workspace(registry: ToolRegistry, ws: Workspace, *,
                      signed_expected: bool, input_size: int, use_cache: bool = True) -> None:
    """Log a one-line apk sanity report, write the JSON report, and point at the layout."""
    package = _package_of(registry, ws.app_apk) or '?'
    report_output_apk(registry, ws.app_apk, package, signed_expected, input_size)
    report_path = ws.reports_dir / const_file_report_json
    write_json(build_report(registry, ws, use_cache=use_cache), report_path)
    logger.info("workspace: %s", ws.root)
    logger.info("  extracted: %s", ws.extracted_dir)
    logger.info("  dumps:     %s", ws.dumps_dir)
    logger.info("  report:    %s", report_path)


def report_for_input(input_path: Path) -> Report:
    """Build a Report for an apk/xapk (ephemeral workspace) or an existing workspace dir.

    Shared by `diff` and `load`: an apk/xapk is extracted into a throwaway workspace
    and reported unsigned; a directory is treated as an existing dumpa workspace.
    """
    config = load_config()
    registry = build_default_registry(config.tool_paths)
    input_abs = input_path.resolve()

    if input_abs.is_dir():
        ws = Workspace(root=input_abs)
        if ws.read_meta() is None:
            raise DumpaError(f"{input_abs} is not a dumpa workspace; pass an .apk/.xapk or run analyze first")
        return build_report(registry, ws)

    in_type = input_type(input_abs)
    if in_type == "xapk":
        prepare_convert(registry, None)
    with open_workspace(None) as ws:
        build_workspace(registry, ws, input_abs, in_type, sha256_file(input_abs), None)
        return build_report(registry, ws)


def analyze(input_file: Path, *, workspace: Path | None = None,
            force: bool = False, signing: str | None = None, use_cache: bool = True) -> None:
    """Extract input_file into a reproducible workspace, reusing it when unchanged."""
    config = load_config()
    registry = build_default_registry(config.tool_paths)
    sign_config = resolve_signing(signing, config, registry)

    input_abs = input_file.resolve()
    in_type = input_type(input_abs)
    if in_type == "xapk":
        prepare_convert(registry, sign_config)

    input_sha = sha256_file(input_abs)
    build_options = _workspace_build_options(in_type, sign_config)
    signed_expected = in_type == "xapk" and sign_config is not None
    ws_path = workspace.resolve() if workspace else Path.cwd() / f'{input_abs.stem}-workspace'

    with open_workspace(ws_path) as ws:
        if decide_reuse(ws, input_sha, force=force, build_options=build_options):
            logger.info("reusing workspace %s (input unchanged)", ws.root)
            meta = ws.read_meta()
            size = meta.input_size if meta else input_abs.stat().st_size
            _report_workspace(registry, ws, signed_expected=signed_expected, input_size=size,
                              use_cache=use_cache)
            return

        build_workspace(registry, ws, input_abs, in_type, input_sha, sign_config, build_options)
        logger.info("workspace ready")
        _report_workspace(registry, ws, signed_expected=signed_expected,
                          input_size=input_abs.stat().st_size, use_cache=use_cache)
