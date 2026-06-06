"""Classify APK splits (main/arch/dpi/locale/assetpack) by file name."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from dumpa.convert.models import (
    ApkPart,
    const_ext_apk,
    const_prefix_apk_split_type_config,
    const_split_apk_type_arch,
    const_split_apk_type_assetpack,
    const_split_apk_type_dpi,
    const_split_apk_type_locale,
    const_split_apk_type_main,
    const_suffix_apk_split_type_assetpack,
    const_suffix_apk_split_type_dpi,
    const_values_apk_split_type_arch,
)
from dumpa.core.errors import XapkToApkError


def determine_split_type_by_apk_file_name(apk_file_name: str, xapk_package_name: str) -> str | None:
    """Classify an APK split as main/arch/dpi/locale/assetpack based on its file name."""
    if (xapk_package_name + const_ext_apk) == apk_file_name or apk_file_name == 'base.apk':
        return const_split_apk_type_main
    if apk_file_name.lower().endswith(const_suffix_apk_split_type_assetpack):
        return const_split_apk_type_assetpack
    if not apk_file_name.startswith(const_prefix_apk_split_type_config):
        return const_split_apk_type_locale
    stem = Path(apk_file_name).stem
    parts = stem.split('.')
    if len(parts) < 2:
        return None
    config_name = parts[1]
    if config_name.endswith(const_suffix_apk_split_type_dpi):
        return const_split_apk_type_dpi
    if config_name in const_values_apk_split_type_arch:
        return const_split_apk_type_arch
    return const_split_apk_type_locale


def get_apks_of_type(parts: Iterable[ApkPart], split_type: str) -> list[ApkPart]:
    """Filter parts by split_type."""
    return [p for p in parts if p.split_type == split_type]


def get_main_apk(parts: Iterable[ApkPart]) -> ApkPart:
    """Return the unique main APK; raises if not present."""
    mains = get_apks_of_type(parts, const_split_apk_type_main)
    if not mains:
        raise XapkToApkError("no main APK found in xapk bundle")
    return mains[0]
