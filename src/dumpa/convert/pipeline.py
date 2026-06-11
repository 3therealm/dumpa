"""Convert pipeline orchestration: extract -> classify -> unpack -> merge -> build.

Owns the tool-registry lifecycle for one conversion run: the registry is built
once in `convert_xapk` and threaded into the phases that resolve external tools,
so the parallel unpack does not re-probe apktool for every split.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any, cast

from dumpa.convert.build import build_single_apk, unpack_apk
from dumpa.convert.classify import (
    determine_split_type_by_apk_file_name,
    get_apks_of_type,
    get_main_apk,
)
from dumpa.convert.manifest import (
    delete_signature_related_files,
    strip_apktool_dummies,
    update_main_manifest_file,
)
from dumpa.convert.merge import (
    merge_apk_arch,
    merge_apk_assets,
    merge_apk_resources,
    prioritize_dpi_apk_list,
)
from dumpa.convert.models import (
    ApkPart,
    StepFailure,
    const_apks_dir_splits,
    const_apks_dir_standalones,
    const_apks_file_universal,
    const_env_unpack_workers,
    const_ext_apk,
    const_file_target_file,
    const_file_xapk_manifest,
    const_file_xapk_manifest_key_package_name,
    const_split_apk_type_arch,
    const_split_apk_type_assetpack,
    const_split_apk_type_dpi,
    const_split_apk_type_locale,
    file_split_name_and_extension,
)
from dumpa.convert.validate import report_output_apk
from dumpa.core.archive import safe_extract_zip
from dumpa.core.config import (
    SigningConfig,
    const_default_validation_timeout,
    const_env_validation_timeout,
    load_config,
)
from dumpa.core.env import env_positive_int
from dumpa.core.errors import ConfigError, ManifestError, ToolNotFoundError, XapkToApkError
from dumpa.core.fs import working_tmp_dir
from dumpa.core.hashing import sha256_file
from dumpa.core.tools import ToolRegistry, build_default_registry
from dumpa.core.workspace import Workspace, decide_reuse, make_meta, open_workspace
from dumpa.signing import preflight_keystore, resolve_signing
from dumpa.tools import aapt

logger = logging.getLogger("dumpa")

_package_name_pattern = re.compile(
    r'^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$'
)


def load_xapk_manifest(manifest_path: Path) -> dict[str, Any]:
    """Load and validate the top-level XAPK manifest."""
    if not manifest_path.is_file():
        raise ManifestError(f"missing {const_file_xapk_manifest}")
    try:
        with manifest_path.open(encoding='UTF-8') as f:
            loaded = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ManifestError(f"invalid {const_file_xapk_manifest}: {e}") from e

    if not isinstance(loaded, dict):
        raise ManifestError(f"{const_file_xapk_manifest} must be a JSON object")
    manifest = cast("dict[str, Any]", loaded)
    package_name = manifest.get(const_file_xapk_manifest_key_package_name)
    if not isinstance(package_name, str) or not _package_name_pattern.fullmatch(package_name):
        raise ManifestError(f"{const_file_xapk_manifest} has invalid package_name")
    return manifest


def phase_extract_xapk(xapk_abs_path: Path, tmp: Path) -> dict[str, Any]:
    """Unzip the xapk in place into tmp, parse manifest.json, return the parsed dict."""
    logger.info("unpacking xapk")
    safe_extract_zip(xapk_abs_path, tmp)

    return load_xapk_manifest(tmp / const_file_xapk_manifest)


def phase_classify_splits(tmp: Path, package_name: str) -> list[ApkPart]:
    """Discover .apk files in tmp and classify each into an ApkPart by split type."""
    parts: list[ApkPart] = []
    for entry in tmp.iterdir():
        if entry.suffix != const_ext_apk or entry.is_dir():
            continue
        split_type = determine_split_type_by_apk_file_name(entry.name, package_name)
        if split_type is None:
            raise XapkToApkError(f'failed to determine split type of {entry.name}')
        parts.append(ApkPart(
            file_name=entry.name,
            file_path=entry.resolve(),
            dir_name=entry.stem,
            dir_path=(tmp / entry.stem).resolve(),
            split_type=split_type,
        ))
    logger.info("xapk file unpacked; %s parts discovered", len(parts))
    return parts


def _resolve_unpack_workers(num_parts: int) -> int:
    """Decide unpack thread count: env override > min(cpu_count, parts, 4)."""
    raw = os.environ.get(const_env_unpack_workers, '').strip()
    if raw:
        if not raw.isdigit() or int(raw) < 1:
            raise ConfigError(f'{const_env_unpack_workers} must be a positive integer')
        return min(int(raw), num_parts)
    cpu = os.cpu_count() or 1
    # Default cap = 4: each apktool JVM holds ~1GB heap; 4x keeps memory bounded on 16GB hosts.
    return max(1, min(cpu, num_parts, 4))


def phase_unpack_splits(registry: ToolRegistry, tmp: Path, parts: list[ApkPart]) -> None:
    """Run apktool d -s on every split (parallel when workers>1); fail-fast on any error."""
    total = len(parts)
    if total == 0:
        return
    tool = registry.resolve('apktool')
    workers = _resolve_unpack_workers(total)
    if workers == 1:
        for index, part in enumerate(parts):
            logger.info("unpacking %s of %s", index + 1, total)
            unpack_apk(tool, tmp, part.file_name, part.split_type)
        return

    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed

    logger.info("unpacking %s splits with %s workers", total, workers)
    counter = [0]
    lock = threading.Lock()

    def _task(part: ApkPart) -> None:
        unpack_apk(tool, tmp, part.file_name, part.split_type)
        with lock:
            counter[0] += 1
            logger.info("unpacked %s of %s (%s)", counter[0], total, part.file_name)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_task, p) for p in parts]
        for fut in as_completed(futures):
            fut.result()


def _safe_merge(part: ApkPart, phase: str, fn: Callable[[], int | None],
                failures: list[StepFailure]) -> int:
    """Run fn(); append a StepFailure on expected merge errors. Returns fn's conflict count."""
    try:
        return fn() or 0
    except (XapkToApkError, OSError, shutil.Error, ValueError, KeyError) as e:
        failures.append(StepFailure(apk_file=part.file_name, phase=phase, error=str(e)))
        return 0


def _drop_split_dir(part: ApkPart) -> None:
    """Free a split's expanded dir once its content is merged into main; cuts peak disk."""
    if part.dir_path.is_dir():
        shutil.rmtree(part.dir_path, ignore_errors=True)


def phase_merge_splits(parts: list[ApkPart]) -> tuple[ApkPart, list[StepFailure]]:
    """Merge arch + dpi + locale + assetpack splits into the main APK dir; collect non-fatal failures.

    Each split's expanded dir is dropped immediately after its merge — peak disk
    falls roughly in proportion to the largest split, not the sum of all splits.
    """
    main = get_main_apk(parts)
    arch_parts = get_apks_of_type(parts, const_split_apk_type_arch)
    dpi_parts = get_apks_of_type(parts, const_split_apk_type_dpi)
    locale_parts = get_apks_of_type(parts, const_split_apk_type_locale)
    assetpack_parts = get_apks_of_type(parts, const_split_apk_type_assetpack)

    failures: list[StepFailure] = []
    conflicts = 0
    for p in arch_parts:
        _safe_merge(p, 'merge_arch',
                    partial(merge_apk_arch, main.dir_path, p.dir_path), failures)
        _drop_split_dir(p)
    for p in prioritize_dpi_apk_list(dpi_parts):
        conflicts += _safe_merge(p, 'merge_resources',
                                 partial(merge_apk_resources, main.dir_path, p.dir_path), failures)
        _drop_split_dir(p)
    for p in locale_parts:
        conflicts += _safe_merge(p, 'merge_resources',
                                 partial(merge_apk_resources, main.dir_path, p.dir_path), failures)
        conflicts += _safe_merge(p, 'merge_assets',
                                 partial(merge_apk_assets, main.dir_path, p.dir_path), failures)
        _drop_split_dir(p)
    for p in assetpack_parts:
        conflicts += _safe_merge(p, 'merge_assets',
                                 partial(merge_apk_assets, main.dir_path, p.dir_path), failures)
        _drop_split_dir(p)

    if conflicts:
        logger.warning("%s file(s) dropped during merge due to a cross-split size conflict "
                       "(first split wins)", conflicts)
    return main, failures


def phase_finalize_main_apk(main: ApkPart) -> None:
    """Strip leftover signature files, drop apktool dummy refs, and rewrite AndroidManifest."""
    delete_signature_related_files(main.dir_path)
    stripped = strip_apktool_dummies(main.dir_path)
    if stripped:
        logger.info("stripped APKTOOL_DUMMY refs from %s merged xml file(s)", stripped)
    update_main_manifest_file(main.dir_path)


def phase_build_and_sign(registry: ToolRegistry, tmp: Path, main: ApkPart,
                         sign: SigningConfig | None) -> None:
    """Repack, zipalign, and (optionally) sign the merged APK in tmp."""
    build_single_apk(registry, tmp, main.dir_path, sign)


def copy_single_apk_to_working_dir(tmp: Path, working_dir: Path, target_name: str) -> Path:
    """Copy tmp/target.apk to <working_dir>/<target_name>.apk; return the destination path."""
    src = tmp / f'{const_file_target_file}{const_ext_apk}'
    if not src.is_file():
        raise XapkToApkError("result apk file not found")
    dst = working_dir / f'{target_name}{const_ext_apk}'
    if dst.is_dir():
        raise XapkToApkError(f"refusing to overwrite directory at {dst}")
    # Same-FS rename (tmp lives inside working_dir): instant. Tmp is wiped after.
    src.replace(dst)
    return dst


def _emit_apk(src: Path, working_dir: Path, target_name: str) -> Path:
    """Copy/link a built apk to <working_dir>/<target_name>.apk, leaving the source intact.

    The persistent-workspace path emits from `ws.app_apk` (the canonical artifact), which
    must survive — so this copies rather than the rename used for the throwaway scratch.
    """
    if not src.is_file():
        raise XapkToApkError("result apk file not found")
    dst = working_dir / f'{target_name}{const_ext_apk}'
    if dst.is_dir():
        raise XapkToApkError(f"refusing to overwrite directory at {dst}")
    if dst.exists():
        dst.unlink()
    shutil.copy2(src, dst)
    return dst


def _verify_required_tools(registry: ToolRegistry, should_sign: bool) -> None:
    """Ensure apktool, zipalign, and (optionally) apksigner are available; exit if not."""
    names = ['apktool', 'zipalign']
    if should_sign:
        names.append('apksigner')
    registry.require(*names)


def _print_merge_failures(failures: list[StepFailure]) -> None:
    """Log a one-line summary plus per-failure detail."""
    logger.error("%s merge step(s) failed:", len(failures))
    for f in failures:
        logger.error("    - %s (%s): %s", f.apk_file, f.phase, f.error)


def prepare_convert(registry: ToolRegistry, sign_config: SigningConfig | None) -> None:
    """Verify the tools the convert pipeline needs and preflight the keystore if signing."""
    _verify_required_tools(registry, should_sign=sign_config is not None)
    if sign_config is not None:
        preflight_keystore(sign_config, registry)


def build_merged_apk(registry: ToolRegistry, scratch: Path, xapk_abs: Path,
                     sign_config: SigningConfig | None) -> tuple[Path, str]:
    """Run extract->classify->unpack->merge->finalize->build inside scratch.

    Returns (path to the built target.apk in scratch, package_name). The reusable
    core shared by the standalone `convert` command and the `analyze` umbrella.
    """
    manifest = phase_extract_xapk(xapk_abs, scratch)
    package_name = manifest[const_file_xapk_manifest_key_package_name]

    parts = phase_classify_splits(scratch, package_name)
    phase_unpack_splits(registry, scratch, parts)

    main_part, failures = phase_merge_splits(parts)
    if failures:
        _print_merge_failures(failures)
        raise XapkToApkError(f"{len(failures)} merge step(s) failed")

    phase_finalize_main_apk(main_part)
    phase_build_and_sign(registry, scratch, main_part, sign_config)

    target = scratch / f'{const_file_target_file}{const_ext_apk}'
    if not target.is_file():
        raise XapkToApkError("result apk file not found")
    return target, package_name


def _dir_has_apk(d: Path) -> bool:
    """True if d directly contains at least one .apk file."""
    return d.is_dir() and any(
        p.is_file() and p.suffix == const_ext_apk for p in d.iterdir())


def _pick_standalone(d: Path) -> Path | None:
    """Choose one standalone apk (alternatives, not splits): prefer an arm64 build."""
    apks = sorted(p for p in d.iterdir() if p.is_file() and p.suffix == const_ext_apk)
    if not apks:
        return None
    for p in apks:
        if 'arm64' in p.name:
            return p
    return apks[0]


def phase_extract_apks(apks_abs_path: Path, tmp: Path) -> tuple[str, Path]:
    """Unzip a .apks bundle into tmp and locate its payload.

    Returns ("single", apk_path) when the bundle is already one complete apk — a
    `universal.apk` or a chosen `standalones/` build, neither of which is merged —
    or ("splits", dir) when it carries complementary split apks to merge. The
    splits dir is bundletool's `splits/` when present, else the archive root
    (SAI-style dumps drop the splits at the top level).
    """
    logger.info("unpacking apks")
    safe_extract_zip(apks_abs_path, tmp)

    universal = tmp / const_apks_file_universal
    if universal.is_file():
        return "single", universal

    standalones = tmp / const_apks_dir_standalones
    if standalones.is_dir():
        picked = _pick_standalone(standalones)
        if picked is not None:
            return "single", picked

    splits = tmp / const_apks_dir_splits
    if _dir_has_apk(splits):
        return "splits", splits
    if _dir_has_apk(tmp):
        return "splits", tmp
    raise XapkToApkError("no apk found in .apks bundle")


def build_merged_apks(registry: ToolRegistry, scratch: Path, apks_abs: Path,
                      sign_config: SigningConfig | None) -> tuple[Path, str | None]:
    """Resolve a .apks bundle to one canonical apk inside scratch.

    A universal/standalone bundle is already complete and returned as-is (no
    apktool round-trip). A split bundle reuses the xapk classify->unpack->merge->
    finalize->build path. Package name is read later from the built apk via aapt
    (a .apks carries no manifest.json), so None is returned here.
    """
    mode, location = phase_extract_apks(apks_abs, scratch)
    if mode == "single":
        return location, None

    # Splits are keyed by file name (base.apk/base-master.apk -> main); the package
    # name is not needed to classify a .apks, so an empty package name is passed.
    parts = phase_classify_splits(location, "")
    phase_unpack_splits(registry, location, parts)

    main_part, failures = phase_merge_splits(parts)
    if failures:
        _print_merge_failures(failures)
        raise XapkToApkError(f"{len(failures)} merge step(s) failed")

    phase_finalize_main_apk(main_part)
    phase_build_and_sign(registry, location, main_part, sign_config)

    target = location / f'{const_file_target_file}{const_ext_apk}'
    if not target.is_file():
        raise XapkToApkError("result apk file not found")
    return target, None


# === Reusable workspace builder (shared by `analyze`, `convert`, `dump-il2cpp`) ===
#
# Extract an APK/XAPK once into a workspace so later commands never re-extract it.
# These live here, beside build_merged_apk, because both the standalone `convert`
# command and the `analyze` umbrella draw from them.


def _validation_timeout() -> int:
    return env_positive_int(const_env_validation_timeout, const_default_validation_timeout)


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


def workspace_build_options(in_type: str, sign_config: SigningConfig | None) -> dict[str, str] | None:
    """Return the build options that affect reusable workspace output."""
    if in_type not in ("xapk", "apks"):
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


def read_package(registry: ToolRegistry, apk: Path) -> str | None:
    """Read the package name from an apk via aapt; None if aapt is unavailable."""
    try:
        tool = registry.resolve('aapt')
    except ToolNotFoundError:
        return None
    return aapt.read_badging(tool, apk, _validation_timeout()).package


def build_workspace(registry: ToolRegistry, ws: Workspace, input_abs: Path,
                    in_type: str, input_sha256: str, sign_config: SigningConfig | None,
                    build_options: dict[str, str] | None = None,
                    optional_scanners: tuple[str, ...] = ()) -> None:
    """Populate a fresh workspace: produce app.apk, extract it, and write the marker."""
    ws.prepare_build()
    if in_type in ("xapk", "apks"):
        # Build merge scratch under the workspace root (same FS -> instant rename of the
        # result), then free it before extracting app.apk to keep peak disk bounded.
        builder = build_merged_apk if in_type == "xapk" else build_merged_apks
        with working_tmp_dir(ws.root) as scratch:
            target, _package = builder(registry, scratch, input_abs, sign_config)
            target.replace(ws.app_apk)
        tool_names = ['apktool', 'zipalign', 'aapt']
        if sign_config is not None:
            tool_names.append('apksigner')
    else:
        shutil.copy2(input_abs, ws.app_apk)
        tool_names = ['aapt']

    safe_extract_zip(ws.app_apk, ws.extracted_dir)
    ws.write_meta(make_meta(
        input_path=input_abs,
        input_sha256=input_sha256,
        input_size=input_abs.stat().st_size,
        input_type=in_type,
        tool_versions=collect_tool_versions(registry, tool_names),
        build_options=build_options,
        optional_scanners=optional_scanners,
    ))


def convert_into_workspace(registry: ToolRegistry, ws: Workspace, xapk_abs: Path,
                           input_sha256: str, sign_config: SigningConfig | None,
                           build_options: dict[str, str] | None, *,
                           force: bool) -> tuple[Path, str | None]:
    """Build the xapk into a reusable workspace, or reuse an unchanged one.

    Returns (canonical app.apk path, package name). When the workspace already matches
    this input + signing, the extraction is reused — no re-merge, no re-extract.
    """
    if decide_reuse(ws, input_sha256, force=force, build_options=build_options):
        logger.info("reusing workspace %s (input unchanged)", ws.root)
    else:
        build_workspace(registry, ws, xapk_abs, "xapk", input_sha256, sign_config, build_options)
    return ws.app_apk, read_package(registry, ws.app_apk)


def convert_xapk(xapk_path: Path, *, signing: str | None = None,
                 workspace: Path | None = None, force: bool = False) -> None:
    """Run all phases for one .xapk, writing the final .apk into the current working directory.

    Pure pipeline entry: takes an explicit path so it is callable from the Typer
    CLI (`dumpa convert`), the legacy argv entrypoint, and as a library function.

    With `workspace`, the merge lands in a reusable workspace (extracted once, with a
    marker) so a later `analyze`/`dump-il2cpp` on that path reuses the extraction; the
    `<stem>.apk` is still emitted into the cwd. Without it, the build is ephemeral.
    """
    config = load_config()
    registry = build_default_registry(config.tool_paths)
    sign_config = resolve_signing(signing, config, registry)
    prepare_convert(registry, sign_config)

    xapk_abs = xapk_path.resolve()
    original_stem, _ = file_split_name_and_extension(xapk_abs.name)

    logger.info("start")
    cwd = Path.cwd().resolve()

    if workspace is None:
        # Ephemeral build: the workspace primitive (wiped on exit, honors DUMPA_KEEP_TMP)
        # without populating extracted/ — nothing here is reused, so don't pay to unzip it.
        with open_workspace(None) as ws:
            _, package_name = build_merged_apk(registry, ws.root, xapk_abs, sign_config)
            final_apk = copy_single_apk_to_working_dir(ws.root, cwd, original_stem)
            report_output_apk(registry, final_apk, package_name, sign_config is not None,
                              xapk_abs.stat().st_size)
    else:
        input_sha = sha256_file(xapk_abs)
        build_options = workspace_build_options("xapk", sign_config)
        with open_workspace(workspace) as ws:
            app_apk, pkg = convert_into_workspace(
                registry, ws, xapk_abs, input_sha, sign_config, build_options, force=force)
            final_apk = _emit_apk(app_apk, cwd, original_stem)
            report_output_apk(registry, final_apk, pkg or '?', sign_config is not None,
                              xapk_abs.stat().st_size)
            logger.info("workspace: %s", ws.root)

    logger.info("complete")
