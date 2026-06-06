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
from dumpa.core.config import SigningConfig, load_config
from dumpa.core.errors import ConfigError, ManifestError, XapkToApkError
from dumpa.core.fs import working_tmp_dir
from dumpa.core.tools import ToolRegistry, build_default_registry
from dumpa.signing import preflight_keystore

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


def _safe_merge(part: ApkPart, phase: str, fn: Callable[[], None],
                failures: list[StepFailure]) -> None:
    """Run fn(); append a StepFailure to failures on expected merge errors."""
    try:
        fn()
    except (XapkToApkError, OSError, shutil.Error, ValueError, KeyError) as e:
        failures.append(StepFailure(apk_file=part.file_name, phase=phase, error=str(e)))


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
    for p in arch_parts:
        _safe_merge(p, 'merge_arch',
                    partial(merge_apk_arch, main.dir_path, p.dir_path), failures)
        _drop_split_dir(p)
    for p in prioritize_dpi_apk_list(dpi_parts):
        _safe_merge(p, 'merge_resources',
                    partial(merge_apk_resources, main.dir_path, p.dir_path), failures)
        _drop_split_dir(p)
    for p in locale_parts:
        _safe_merge(p, 'merge_resources',
                    partial(merge_apk_resources, main.dir_path, p.dir_path), failures)
        _safe_merge(p, 'merge_assets',
                    partial(merge_apk_assets, main.dir_path, p.dir_path), failures)
        _drop_split_dir(p)
    for p in assetpack_parts:
        _safe_merge(p, 'merge_assets',
                    partial(merge_apk_assets, main.dir_path, p.dir_path), failures)
        _drop_split_dir(p)

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


def convert_xapk(xapk_path: Path) -> None:
    """Run all phases for one .xapk, writing the final .apk into the current working directory.

    Pure pipeline entry: takes an explicit path so it is callable from the Typer
    CLI (`dumpa convert`), the legacy argv entrypoint, and as a library function.
    """
    config = load_config()
    registry = build_default_registry(config.tool_paths)
    sign_config = config.signing
    _verify_required_tools(registry, should_sign=sign_config is not None)
    if sign_config is not None:
        preflight_keystore(sign_config, registry)

    xapk_abs = xapk_path.resolve()
    original_stem, _ = file_split_name_and_extension(xapk_abs.name)

    logger.info("start")
    cwd = Path.cwd().resolve()

    with working_tmp_dir(cwd) as tmp:
        manifest = phase_extract_xapk(xapk_abs, tmp)
        package_name = manifest[const_file_xapk_manifest_key_package_name]

        parts = phase_classify_splits(tmp, package_name)
        phase_unpack_splits(registry, tmp, parts)

        main_part, failures = phase_merge_splits(parts)
        if failures:
            _print_merge_failures(failures)
            raise XapkToApkError(f"{len(failures)} merge step(s) failed")

        phase_finalize_main_apk(main_part)
        phase_build_and_sign(registry, tmp, main_part, sign_config)

        final_apk = copy_single_apk_to_working_dir(tmp, cwd, original_stem)
        report_output_apk(registry, final_apk, package_name, sign_config is not None,
                          xapk_abs.stat().st_size)

    logger.info("complete")
