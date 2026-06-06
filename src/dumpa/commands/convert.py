#!/usr/bin/python3

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sys
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any
from zipfile import BadZipFile, ZipFile

from dumpa.commands.base import run_command
from dumpa.core.archive import _safe_extract_zip
from dumpa.core.config import (
    SigningConfig,
    const_default_validation_timeout,
    const_env_validation_timeout,
    load_config,
)
from dumpa.core.env import _env_positive_int
from dumpa.core.errors import (
    ManifestError,
    ToolExecutionError,
    ToolNotFoundError,
    XapkToApkError,
)
from dumpa.core.fs import _link_or_copy, delete_file_if_exists, working_tmp_dir
from dumpa.core.logging import configure_logging
from dumpa.core.tools import ResolvedTool, build_default_registry
from dumpa.signing import preflight_keystore
from dumpa.tools import aapt, apksigner, apktool, zipalign

# === SECTION: Constants ===

const_file_target_file = "target"
const_ext_apk = ".apk"
const_ext_xapk = ".xapk"
const_ext_zip = ".zip"

const_file_xapk_manifest = "manifest.json"
const_file_xapk_manifest_key_package_name = "package_name"

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

logger = logging.getLogger("dumpa")

# Single registry instance for the run: resolves once, reused across phases so the
# parallel unpack does not re-probe apktool for every split.
_REGISTRY = build_default_registry()


# === SECTION: Data classes ===

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


# === SECTION: CLI argument helpers ===

def print_help() -> None:
    """Print CLI usage."""
    sys.stdout.write(
        "\n"
        "Convert a split .xapk bundle into a single installable .apk.\n"
        "Usage: dumpa convert PATH_TO_FILE.xapk\n"
        "\n"
    )


def get_param_xapk_file_name() -> str:
    """Return the raw xapk argument from argv."""
    return sys.argv[1]


def get_param_xapk_abs_path() -> Path:
    """Return the absolute path to the input xapk."""
    return Path(get_param_xapk_file_name()).resolve()


def check_sys_args() -> bool:
    """Validate argv: exactly one .xapk path that exists."""
    if len(sys.argv) != 2:
        return False
    name = get_param_xapk_file_name()
    if not name.endswith(const_ext_xapk):
        return False
    return Path(name).resolve().is_file()


def file_split_name_and_extension(file_path: str) -> tuple[str, str]:
    """Split a filename into (stem, suffix); suffix includes the leading dot."""
    p = Path(file_path)
    return p.stem, p.suffix


# === SECTION: Apktool config parsing ===

def get_do_not_compress_lines(config_file_lines: list[str]) -> tuple[list[str], int, int]:
    """Locate the `doNotCompress:` block in apktool.yml lines; return (lines, start_idx, end_idx).

    `start_idx` is the index of the first list item line (after the `doNotCompress:` header).
    `end_idx` is the index one past the last list item line (suitable for a Python slice).
    Returns (-1, -1) for both when the block is absent.
    """
    index_start = -1
    index_end = -1
    result: list[str] = []
    start_block_literal = 'doNotCompress:'
    prefix_target_line = '- '
    opened = False
    for index, line in enumerate(config_file_lines):
        if not opened and line.startswith(start_block_literal):
            opened = True
            index_start = index + 1
        elif opened and line.startswith(prefix_target_line):
            result.append(line)
        elif opened and not line.startswith(prefix_target_line):
            index_end = index
            break
    if opened and index_end == -1:
        # Block ran to EOF without a trailing non-`-` line.
        index_end = len(config_file_lines)
    result.sort()
    return result, index_start, index_end


def parse_apktool_config(config_file_path: Path) -> ApktoolConfig:
    """Parse apktool.yml into an ApktoolConfig dataclass."""
    with config_file_path.open(encoding='UTF-8') as f:
        lines = f.readlines()
    do_not_compress_lines, idx_start, idx_end = get_do_not_compress_lines(lines)
    return ApktoolConfig(lines, do_not_compress_lines, idx_start, idx_end)


def insert_new_lines_do_not_compress(config_file_path: Path, lines_to_insert: list[str]) -> None:
    """Merge lines into the `doNotCompress:` block (sorted, dedup) and rewrite the file.

    If the file has no `doNotCompress:` block, append a new one at EOF.
    """
    cfg = parse_apktool_config(config_file_path)
    merged = sorted(set(cfg.lines_do_not_compress) | set(lines_to_insert))

    updated = list(cfg.lines_all)
    if cfg.lines_do_not_compress_index_start == -1:
        # No existing block: append a fresh one. Ensure prior content ends with newline.
        if updated and not updated[-1].endswith('\n'):
            updated[-1] = updated[-1] + '\n'
        updated.append('doNotCompress:\n')
        updated.extend(merged)
    else:
        updated[cfg.lines_do_not_compress_index_start:cfg.lines_do_not_compress_index_end] = merged
    with config_file_path.open('w', encoding='UTF-8') as f:
        f.writelines(updated)


# === SECTION: Split classification ===

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


# === SECTION: Merge helpers ===

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
    _link_or_copy(src, dst)


def merge_apk_arch(dir_apk_main: Path, dir_apk_arch: Path) -> None:
    """Merge an architecture split's lib/ tree and apktool.yml entries into the main APK dir."""
    path_libs_src = dir_apk_arch / const_apk_dir_lib
    path_libs_dst = dir_apk_main / const_apk_dir_lib
    path_libs_dst.mkdir(exist_ok=True)

    for entry in path_libs_src.iterdir():
        shutil.copytree(entry, path_libs_dst / entry.name, copy_function=_link_or_copy)

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


def merge_apk_resources(dir_apk_main: Path, dir_apk_with_resources: Path) -> None:
    """Merge a resource split's res/ tree into the main APK dir; preserve existing files."""
    target_res_dir = dir_apk_main / 'res'
    res_dir = dir_apk_with_resources / 'res'
    if not res_dir.exists():
        return
    target_res_dir.mkdir(parents=True, exist_ok=True)

    existing = _existing_rel_files(target_res_dir)
    for src, rel in iter_resource_files(res_dir, ('values', 'public.xml')):
        if rel in existing:
            continue
        copy_resource_file(src, target_res_dir / rel)
        existing.add(rel)


def merge_apk_assets(dir_apk_main: Path, dir_apk_with_asset_pack: Path) -> None:
    """Merge any assets/ tree from a split into the main APK; preserve existing files.

    Handles both classic Play Asset Delivery layouts (assets/assetpack/...) and
    Unity-style asset packs (assets/<PackName>/...) by walking the entire assets/ tree.
    """
    src_assets = dir_apk_with_asset_pack / 'assets'
    if not src_assets.exists():
        return
    target_assets = dir_apk_main / 'assets'
    target_assets.mkdir(parents=True, exist_ok=True)

    existing = _existing_rel_files(target_assets)
    for src, rel in iter_resource_files(src_assets, None):
        if rel in existing:
            continue
        copy_resource_file(src, target_assets / rel)
        existing.add(rel)

    cfg_path = dir_apk_with_asset_pack / const_apk_file_apktool_config
    if cfg_path.exists():
        cfg_src = parse_apktool_config(cfg_path)
        insert_new_lines_do_not_compress(dir_apk_main / const_apk_file_apktool_config,
                                         cfg_src.lines_do_not_compress)


# === SECTION: DPI prioritization ===

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


# === SECTION: Build pipeline ===

# Per-split-type apktool decode flags. `-s` skips smali disassembly (classes.dex
# stays in original/ so the rebuilt apk is identical). `-r` skips resource decode.
# Splits that contribute only lib/ or assets/ skip both — saves a pass over the
# resource table and significant wall time on big asset packs.
_UNPACK_FLAGS_BY_TYPE: dict[str, tuple[str, ...]] = {
    const_split_apk_type_main: ('-s',),
    const_split_apk_type_arch: ('-r', '-s'),
    const_split_apk_type_dpi: ('-s',),
    const_split_apk_type_locale: ('-s',),
    const_split_apk_type_assetpack: ('-r', '-s'),
}


def unpack_apk(tool: ResolvedTool, path_dir_tmp: Path, apk_file: str, split_type: str) -> None:
    """Unpack a single APK into the tmp dir via apktool, then delete the source split."""
    flags = _UNPACK_FLAGS_BY_TYPE.get(split_type, ('-s',))
    apktool.decode(tool, apk_file, path_dir_tmp, flags)
    (path_dir_tmp / apk_file).unlink()


def pack_apk(tool: ResolvedTool, path_dir_tmp: Path, main_apk_dir: Path) -> None:
    """Repack the merged main APK dir via apktool into tmp/target.apk."""
    logger.info("repack apk")
    built = apktool.build(tool, main_apk_dir)
    target = path_dir_tmp / f'{const_file_target_file}{const_ext_apk}'
    # Same-FS rename: instant. No copy of the (possibly hundreds of MB) built apk.
    built.replace(target)


def zipalign_apk(tool: ResolvedTool, path_dir_tmp: Path) -> None:
    """Run `zipalign -p -f 4` on tmp/target.apk in-place."""
    logger.info("zipalign apk")
    target = path_dir_tmp / f'{const_file_target_file}{const_ext_apk}'
    if not target.exists():
        raise XapkToApkError("result apk not found")

    aligned = path_dir_tmp / f'aligned_{const_file_target_file}{const_ext_apk}'
    if aligned.exists():
        aligned.unlink()

    zipalign.align(tool, target, aligned)
    if not aligned.exists():
        raise XapkToApkError("failed to zipalign apk (output missing)")
    aligned.replace(target)


def build_single_apk(path_dir_tmp: Path, main_apk_dir: Path, sign: SigningConfig | None) -> None:
    """Repack, zipalign, and optionally sign the merged APK."""
    pack_apk(_REGISTRY.resolve('apktool'), path_dir_tmp, main_apk_dir)
    zipalign_apk(_REGISTRY.resolve('zipalign'), path_dir_tmp)
    if sign is not None:
        sign_apk(_REGISTRY.resolve('apksigner'), path_dir_tmp, sign)
    else:
        logger.info("skip signing apk")


# === SECTION: Sign + verify ===

def sign_apk(tool: ResolvedTool, path_dir_tmp: Path, sign: SigningConfig) -> None:
    """Sign tmp/target.apk via apksigner; verify v2+v3 schemes; print SHA-256."""
    target = path_dir_tmp / f'{const_file_target_file}{const_ext_apk}'
    if not target.exists():
        raise XapkToApkError("result apk not found")

    logger.info("resign apk")
    apksigner.sign(
        tool, target,
        keystore=sign.keystore_file,
        key_alias=sign.key_alias,
        keystore_password_env=sign.keystore_password_env,
        key_password_env=sign.key_password_env,
        min_sdk_version=sign.min_sdk_version,
    )

    out = apksigner.verify(
        tool, target,
        _env_positive_int(const_env_validation_timeout, const_default_validation_timeout),
    )
    if 'Verified using v2 scheme (APK Signature Scheme v2): true' not in out \
            or 'Verified using v3 scheme (APK Signature Scheme v3): true' not in out:
        logger.error("%s", out)
        raise XapkToApkError('apksigner verify did not confirm v2+v3 schemes')

    sha256: str | None = None
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith('Signer #1 certificate SHA-256 digest:'):
            sha256 = stripped.split(':', 1)[1].strip()
            break
    if sha256:
        logger.info("signed with SHA-256: %s", sha256)
    else:
        logger.info("signature verified (v2+v3)")


# === SECTION: Manifest finalization ===

def delete_signature_related_files(path_to_main_apk: Path) -> None:
    """Remove the bundled META-INF entries left behind by apktool.

    Splits may carry CERT.* or other arbitrarily-named signature blocks; apksigner
    refuses to sign if any leftover *.RSA/*.SF/*.DSA/*.EC/*.MF remain.
    """
    meta_inf = path_to_main_apk / 'original' / 'META-INF'
    if not meta_inf.is_dir():
        return
    for ext in ('RSA', 'SF', 'DSA', 'EC', 'MF'):
        for f in meta_inf.glob(f'*.{ext}'):
            delete_file_if_exists(f)


_split_attr_pattern = re.compile(
    r'\s+android:(?:isSplitRequired|requiredSplitTypes|splitTypes)="[^"]*"'
)


# Matches a single XML element on its own line whose tag (or attribute) contains
# APKTOOL_DUMMY_*. Covers: <attr .../>, <public .../>, <item ...>val</item>.
_apktool_dummy_line = re.compile(
    r'^[ \t]*<[^>]*\bAPKTOOL_DUMMY_[^>]*>(?:[^<\n]*</\w+>)?[ \t]*\n',
    re.MULTILINE,
)


def strip_apktool_dummies(main_apk_dir: Path) -> int:
    """Remove APKTOOL_DUMMY_* placeholder entries from merged values XML.

    Apktool emits APKTOOL_DUMMY_<hex> when decoding a config split alone — those
    attr IDs only resolve in the base apk's public table. Once merged into base,
    aapt2 link rejects the dummies at rebuild. Stripping is safe: real attrs
    defined in base remain; only unresolvable per-config overrides are dropped.

    Returns the number of XML files modified.
    """
    res_dir = main_apk_dir / 'res'
    if not res_dir.is_dir():
        return 0
    modified = 0
    for top in res_dir.iterdir():
        if not top.is_dir() or not top.name.startswith('values'):
            continue
        for xml_path in top.rglob('*.xml'):
            text = xml_path.read_text(encoding='UTF-8')
            if 'APKTOOL_DUMMY_' not in text:
                continue
            new_text = _apktool_dummy_line.sub('', text)
            if new_text != text:
                xml_path.write_text(new_text, encoding='UTF-8')
                modified += 1
    return modified


def update_main_manifest_file(path_main_apk: Path) -> None:
    """Strip split-bundle attributes from the merged AndroidManifest.xml."""
    path_manifest = path_main_apk / 'AndroidManifest.xml'

    literal_replacements = {
        '<meta-data android:name="com.google.firebase.messaging.default_notification_icon" android:resource="@null"/>': '',
        'android:value="STAMP_TYPE_DISTRIBUTION_APK"': 'android:value="STAMP_TYPE_STANDALONE_APK"',
        '<meta-data android:name="com.android.vending.splits.required" android:value="true"/>': '',
        '<meta-data android:name="com.android.vending.splits" android:resource="@xml/splits0"/>': '',
    }

    with path_manifest.open(encoding='UTF-8') as f:
        data = f.read()
    # Strip split-related attrs regardless of value; eat leading whitespace to avoid double-spaces.
    data = _split_attr_pattern.sub('', data)
    for from_str, to_str in literal_replacements.items():
        data = data.replace(from_str, to_str)
    # Atomic swap so a crash mid-write cannot corrupt the manifest.
    tmp_path = path_manifest.with_suffix('.xml.tmp')
    with tmp_path.open('w', encoding='UTF-8') as f:
        f.write(data)
    tmp_path.replace(path_manifest)


# === SECTION: Validation ===

def _parse_aapt_badging(apk_path: Path) -> tuple[str | None, str | None, str | None]:
    """Read package badging from apk_path via aapt; (None, None, None) if unavailable."""
    try:
        tool = _REGISTRY.resolve('aapt')
    except ToolNotFoundError:
        return (None, None, None)
    return aapt.badging(
        tool, apk_path,
        _env_positive_int(const_env_validation_timeout, const_default_validation_timeout),
    )


def verify_zipalign(apk_path: Path) -> str | None:
    """Verify 4-byte alignment via zipalign; returns error message or None."""
    try:
        tool = _REGISTRY.resolve('zipalign')
    except ToolNotFoundError:
        return None
    try:
        zipalign.check(
            tool, apk_path,
            _env_positive_int(const_env_validation_timeout, const_default_validation_timeout),
        )
    except ToolExecutionError as e:
        return str(e)
    return None


def verify_zip_crc(apk_path: Path) -> str | None:
    """ZipFile.testzip() — read every entry's CRC; returns first bad name or None."""
    try:
        with ZipFile(apk_path, 'r') as zf:
            bad = zf.testzip()
    except (BadZipFile, OSError, RuntimeError) as e:
        return f'zip CRC scan failed: {e}'
    if bad:
        return f'zip entry CRC bad: {bad}'
    return None


def report_output_apk(apk_path: Path, expected_pkg: str, signed_expected: bool,
                      input_size_bytes: int) -> None:
    """Inspect the final APK; print a one-line sanity report plus any integrity issues."""
    if not apk_path.is_file():
        logger.warning("output apk missing: %s", apk_path)
        return

    size_mb = apk_path.stat().st_size / (1024.0 * 1024.0)
    issues: list[str] = []

    crc_err = verify_zip_crc(apk_path)
    if crc_err:
        issues.append(crc_err)

    has_manifest = has_dex = has_signature = False
    entry_count = 0
    try:
        with ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                entry_count += 1
                if name == 'AndroidManifest.xml':
                    has_manifest = True
                elif name.startswith('classes') and name.endswith('.dex'):
                    has_dex = True
                elif name.startswith('META-INF/') and (name.endswith('.RSA') or name.endswith('.EC') or name.endswith('.DSA')):
                    has_signature = True
    except (BadZipFile, OSError, RuntimeError) as e:
        issues.append(f'apk inspect failed: {e}')

    if not has_manifest:
        issues.append('missing AndroidManifest.xml')
    if not has_dex:
        issues.append('missing classes.dex')
    if signed_expected and not has_signature:
        issues.append('expected signature block missing')

    align_err = verify_zipalign(apk_path)
    if align_err:
        issues.append(align_err)

    aapt_pkg, _, aapt_ver = _parse_aapt_badging(apk_path)
    if aapt_pkg and aapt_pkg != expected_pkg:
        issues.append(f'package mismatch: apk={aapt_pkg!r} expected={expected_pkg!r}')

    if input_size_bytes > 0:
        ratio = apk_path.stat().st_size / input_size_bytes
        if ratio < 0.5:
            in_mb = input_size_bytes / (1024.0 * 1024.0)
            issues.append(f'output {size_mb:.1f}MB << input {in_mb:.1f}MB (ratio {ratio:.0%}); merge may have lost data')

    summary = f'[*] result: {size_mb:.2f} MB, {entry_count} entries, package={expected_pkg}'
    if aapt_ver:
        summary += f', version={aapt_ver}'
    summary += f', signed={has_signature}'
    logger.info("%s", summary)
    if issues:
        for issue in issues:
            logger.warning("%s", issue)


# === SECTION: Phases ===

_package_name_pattern = re.compile(
    r'^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$'
)


def load_xapk_manifest(manifest_path: Path) -> dict[str, Any]:
    """Load and validate the top-level XAPK manifest."""
    if not manifest_path.is_file():
        raise ManifestError(f"missing {const_file_xapk_manifest}")
    try:
        with manifest_path.open(encoding='UTF-8') as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ManifestError(f"invalid {const_file_xapk_manifest}: {e}") from e

    if not isinstance(manifest, dict):
        raise ManifestError(f"{const_file_xapk_manifest} must be a JSON object")
    package_name = manifest.get(const_file_xapk_manifest_key_package_name)
    if not isinstance(package_name, str) or not _package_name_pattern.fullmatch(package_name):
        raise ManifestError(f"{const_file_xapk_manifest} has invalid package_name")
    return manifest


def phase_extract_xapk(xapk_abs_path: Path, tmp: Path) -> dict[str, Any]:
    """Unzip the xapk in place into tmp, parse manifest.json, return the parsed dict."""
    logger.info("unpacking xapk")
    _safe_extract_zip(xapk_abs_path, tmp)

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
            raise SystemExit(f'{const_env_unpack_workers} must be a positive integer')
        return min(int(raw), num_parts)
    cpu = os.cpu_count() or 1
    # Default cap = 4: each apktool JVM holds ~1GB heap; 4x keeps memory bounded on 16GB hosts.
    return max(1, min(cpu, num_parts, 4))


def phase_unpack_splits(tmp: Path, parts: list[ApkPart]) -> None:
    """Run apktool d -s on every split (parallel when workers>1); fail-fast on any error."""
    total = len(parts)
    if total == 0:
        return
    tool = _REGISTRY.resolve('apktool')
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


def phase_build_and_sign(tmp: Path, main: ApkPart, sign: SigningConfig | None) -> None:
    """Repack, zipalign, and (optionally) sign the merged APK in tmp."""
    build_single_apk(tmp, main.dir_path, sign)


# === SECTION: CLI entry ===

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


def _verify_required_tools(should_sign: bool) -> None:
    """Ensure apktool, zipalign, and (optionally) apksigner are available; exit if not."""
    names = ['apktool', 'zipalign']
    if should_sign:
        names.append('apksigner')
    _REGISTRY.require(*names)


def _print_merge_failures(failures: list[StepFailure]) -> None:
    """Log a one-line summary plus per-failure detail."""
    logger.error("%s merge step(s) failed:", len(failures))
    for f in failures:
        logger.error("    - %s (%s): %s", f.apk_file, f.phase, f.error)


def convert_xapk(xapk_path: Path) -> None:
    """Run all phases for one .xapk, writing the final .apk next to the source.

    Pure pipeline entry: takes an explicit path so it is callable from the Typer
    CLI (`dumpa convert`), the legacy argv entrypoint, and as a library function.
    """
    global _REGISTRY
    config = load_config()
    _REGISTRY = build_default_registry(config.tool_paths)
    sign_config = config.signing
    _verify_required_tools(should_sign=sign_config is not None)
    if sign_config is not None:
        preflight_keystore(sign_config, _REGISTRY)

    xapk_abs = xapk_path.resolve()
    original_stem, _ = file_split_name_and_extension(xapk_abs.name)

    logger.info("start")
    cwd = Path.cwd().resolve()

    with working_tmp_dir(cwd) as tmp:
        manifest = phase_extract_xapk(xapk_abs, tmp)
        package_name = manifest[const_file_xapk_manifest_key_package_name]

        parts = phase_classify_splits(tmp, package_name)
        phase_unpack_splits(tmp, parts)

        main_part, failures = phase_merge_splits(parts)
        if failures:
            _print_merge_failures(failures)
            raise XapkToApkError(f"{len(failures)} merge step(s) failed")

        phase_finalize_main_apk(main_part)
        phase_build_and_sign(tmp, main_part, sign_config)

        final_apk = copy_single_apk_to_working_dir(tmp, cwd, original_stem)
        report_output_apk(final_apk, package_name, sign_config is not None,
                          xapk_abs.stat().st_size)

    logger.info("complete")


def _run_with_profile(profile_target: str, xapk_path: Path) -> None:
    """Run convert_xapk under cProfile; dump stats to file, print top 20 by cumtime."""
    import cProfile
    import pstats
    from pstats import SortKey

    profiler = cProfile.Profile()
    profiler.enable()
    try:
        convert_xapk(xapk_path)
    finally:
        profiler.disable()
        out_path = Path(profile_target if profile_target != '1' else '.dumpa-profile.prof').resolve()
        stats = pstats.Stats(profiler).sort_stats(SortKey.CUMULATIVE)
        stats.dump_stats(str(out_path))
        logger.info("profile written to %s", out_path)
        logger.info("top 20 by cumulative time:")
        stats.print_stats(20)


def run_convert(xapk_path: Path) -> None:
    """Run conversion, honoring the profile env var.

    Mapping exceptions to exit codes is the caller's responsibility (run_command).
    """
    profile_target = os.environ.get(const_env_profile, '').strip()
    if profile_target:
        _run_with_profile(profile_target, xapk_path)
    else:
        convert_xapk(xapk_path)


def main() -> None:
    """Legacy argv entrypoint: `python -m dumpa.commands.convert app.xapk`."""
    if not check_sys_args():
        print_help()
        sys.exit(-1)
    configure_logging()
    run_command(lambda: run_convert(get_param_xapk_abs_path()))


if __name__ == '__main__':
    main()
