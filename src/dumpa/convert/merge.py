"""Merge arch/dpi/locale/assetpack splits into the main APK directory."""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterable, Iterator
from pathlib import Path

from dumpa.convert.apktool_config import insert_new_lines_do_not_compress, parse_apktool_config
from dumpa.convert.models import (
    ApkPart,
    const_apk_dir_lib,
    const_apk_file_apktool_config,
)
from dumpa.core.fs import link_or_copy


def iter_resource_files(res_dir: Path, skip_parts: tuple[str, ...] | None) -> Iterator[tuple[Path, Path]]:
    """Yield (src, rel_path) tuples for files under res_dir.

    `skip_parts` is a tuple of trailing path components to skip (e.g. ('values', 'public.xml')).
    Pass None to skip nothing. Comparison is on path components, not string suffix, so it is
    stable across OS path separators.
    """
    for root, _dirs, files in os.walk(res_dir):
        root_path = Path(root)
        for fname in files:
            src = root_path / fname
            rel = src.relative_to(res_dir)
            if skip_parts and rel.parts[-len(skip_parts):] == skip_parts:
                continue
            yield src, rel


def copy_resource_file(src: Path, dst: Path) -> None:
    """Place a single file at dst (hardlink when possible), creating parent dirs as needed."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    link_or_copy(src, dst)


def merge_apk_arch(dir_apk_main: Path, dir_apk_arch: Path) -> None:
    """Merge an architecture split's lib/ tree and apktool.yml entries into the main APK dir."""
    path_libs_src = dir_apk_arch / const_apk_dir_lib
    path_libs_dst = dir_apk_main / const_apk_dir_lib
    path_libs_dst.mkdir(exist_ok=True)

    for entry in path_libs_src.iterdir():
        shutil.copytree(entry, path_libs_dst / entry.name, copy_function=link_or_copy)

    cfg_src = parse_apktool_config(dir_apk_arch / const_apk_file_apktool_config)
    insert_new_lines_do_not_compress(dir_apk_main / const_apk_file_apktool_config,
                                     cfg_src.lines_do_not_compress)


def _existing_rel_files(target_dir: Path) -> set[Path]:
    """Pre-walk target_dir once; returns a set of relative paths of existing files.
    Replaces a per-file dst.exists() stat with one O(1) set lookup. Newly-written
    files get added by the caller as they land.
    """
    if not target_dir.is_dir():
        return set()
    out: set[Path] = set()
    for root, _dirs, files in os.walk(target_dir):
        root_path = Path(root)
        for fname in files:
            out.add((root_path / fname).relative_to(target_dir))
    return out


def _is_size_conflict(src: Path, dst: Path) -> bool:
    """True if a kept file and an incoming same-path file differ in size.

    A cheap proxy for a real cross-split content conflict (vs. a benign byte-identical
    duplicate). First-wins still applies; this only surfaces that something was dropped.
    """
    try:
        return dst.is_file() and src.stat().st_size != dst.stat().st_size
    except OSError:
        return False


def merge_apk_resources(dir_apk_main: Path, dir_apk_with_resources: Path) -> int:
    """Merge a resource split's res/ tree into the main APK dir; preserve existing files.

    Returns the count of dropped files whose size differed from the kept one (a likely
    real conflict, not a byte-identical duplicate).
    """
    target_res_dir = dir_apk_main / 'res'
    res_dir = dir_apk_with_resources / 'res'
    if not res_dir.exists():
        return 0
    target_res_dir.mkdir(parents=True, exist_ok=True)

    existing = _existing_rel_files(target_res_dir)
    conflicts = 0
    for src, rel in iter_resource_files(res_dir, ('values', 'public.xml')):
        if rel in existing:
            if _is_size_conflict(src, target_res_dir / rel):
                conflicts += 1
            continue
        copy_resource_file(src, target_res_dir / rel)
        existing.add(rel)
    return conflicts


def merge_apk_assets(dir_apk_main: Path, dir_apk_with_asset_pack: Path) -> int:
    """Merge any assets/ tree from a split into the main APK; preserve existing files.

    Handles both classic Play Asset Delivery layouts (assets/assetpack/...) and
    Unity-style asset packs (assets/<PackName>/...) by walking the entire assets/ tree.
    Returns the count of dropped same-path files whose size differed from the kept one.
    """
    src_assets = dir_apk_with_asset_pack / 'assets'
    if not src_assets.exists():
        return 0
    target_assets = dir_apk_main / 'assets'
    target_assets.mkdir(parents=True, exist_ok=True)

    existing = _existing_rel_files(target_assets)
    conflicts = 0
    for src, rel in iter_resource_files(src_assets, None):
        if rel in existing:
            if _is_size_conflict(src, target_assets / rel):
                conflicts += 1
            continue
        copy_resource_file(src, target_assets / rel)
        existing.add(rel)

    cfg_path = dir_apk_with_asset_pack / const_apk_file_apktool_config
    if cfg_path.exists():
        cfg_src = parse_apktool_config(cfg_path)
        insert_new_lines_do_not_compress(dir_apk_main / const_apk_file_apktool_config,
                                         cfg_src.lines_do_not_compress)
    return conflicts


def prioritize_dpi_apk_list_rev_sort(apks_dpi: Iterable[ApkPart]) -> list[ApkPart]:
    """Sort dpi parts by file name, descending (highest density first)."""
    return sorted(apks_dpi, key=lambda x: x.file_name, reverse=True)


def prioritize_dpi_apk_list(apks_dpi: list[ApkPart]) -> list[ApkPart]:
    """Order dpi splits xxxhdpi → ldpi by `dir_name`; unknowns appended in reverse-sort order."""
    preferred = ['config.xxxhdpi', 'config.xxhdpi', 'config.xhdpi', 'config.hdpi',
                 'config.mdpi', 'config.ldpi', 'config.nodpi', 'config.tvdpi']

    by_dir: dict[str, ApkPart] = {p.dir_name: p for p in apks_dpi}
    ordered: list[ApkPart] = []
    for key in preferred:
        if key in by_dir:
            ordered.append(by_dir.pop(key))
    if by_dir:
        ordered.extend(prioritize_dpi_apk_list_rev_sort(by_dir.values()))
    return ordered
