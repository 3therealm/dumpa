"""Shared constants and data classes for the xapk->apk convert pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# === Constants ===

const_file_target_file = "target"
const_ext_apk = ".apk"
const_ext_xapk = ".xapk"
const_ext_apks = ".apks"
const_ext_zip = ".zip"

const_file_xapk_manifest = "manifest.json"
const_file_xapk_manifest_key_package_name = "package_name"

# .apks (bundletool / `bundletool build-apks`) layout markers.
const_apks_file_universal = "universal.apk"
const_apks_dir_splits = "splits"
const_apks_dir_standalones = "standalones"

const_prefix_apk_split_type_config = "config"
const_suffix_apk_split_type_dpi = "dpi"
const_values_apk_split_type_arch = ["arm64_v8a", "armeabi_v7a", "armeabi", "x86", "x86_64"]

const_split_apk_type_main = "main"
const_split_apk_type_arch = "arch"
const_split_apk_type_dpi = "dpi"
const_split_apk_type_locale = "locale"
const_split_apk_type_assetpack = "assetpack"

const_suffix_apk_split_type_assetpack = "assetpack.apk"

const_apk_file_apktool_config = 'apktool.yml'
const_apk_dir_lib = 'lib'

const_env_profile = 'DUMPA_PROFILE'
const_env_unpack_workers = 'DUMPA_UNPACK_WORKERS'


# === Data classes ===

@dataclass
class ApkPart:
    """A single APK split discovered inside the source XAPK."""
    file_name: str
    file_path: Path
    dir_name: str
    dir_path: Path
    split_type: str


@dataclass
class StepFailure:
    """A non-fatal error captured during a batch merge step."""
    apk_file: str
    phase: str
    error: str


@dataclass
class ApktoolConfig:
    """Parsed apktool.yml fragments needed for merging."""
    lines_all: list[str]
    lines_do_not_compress: list[str]
    lines_do_not_compress_index_start: int
    lines_do_not_compress_index_end: int


def file_split_name_and_extension(file_path: str) -> tuple[str, str]:
    """Split a filename into (stem, suffix); suffix includes the leading dot."""
    p = Path(file_path)
    return p.stem, p.suffix
