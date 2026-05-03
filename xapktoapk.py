#!/usr/bin/python3

from __future__ import annotations

import datetime
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any, Callable, Generator, Iterable, Iterator
from zipfile import ZipFile

# === SECTION: Constants ===

const_dir_tmp = ".xapktoapk"
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

const_env_keystore_file = 'XAPKTOAPK_KEYSTORE_FILE'
const_env_keystore_password = 'XAPKTOAPK_KEYSTORE_PASSWORD'
const_env_key_alias = 'XAPKTOAPK_KEY_ALIAS'
const_env_key_password = 'XAPKTOAPK_KEY_PASSWORD'
const_env_min_sdk_version = 'XAPKTOAPK_MIN_SDK_VERSION'


# === SECTION: Data classes ===

@dataclass(frozen=True)
class SignConfig:
    """Signing parameters resolved from environment."""
    keystore_file: Path
    key_alias: str
    min_sdk_version: int | None = None
    keystore_password_env: str = const_env_keystore_password
    key_password_env: str = const_env_key_password


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
    print("")
    print("XapkToApk is a tool that converts .xapk file into .apk file")
    print("Can be useful if you want to build a classic fat apk from splitted app bundle")
    print("Usage: python xapktoapk.py PATH_TO_FILE.xapk")
    print("")


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
    return Path(name).resolve().exists()


def file_split_name_and_extension(file_path: str) -> tuple[str, str]:
    """Split a filename into (stem, suffix); suffix includes the leading dot."""
    p = Path(file_path)
    return p.stem, p.suffix


# === SECTION: Subprocess primitives ===

def run(cmd: list[str],
        cwd: Path | None = None,
        fail_msg: str | None = None,
        extra_env: dict[str, str] | None = None,
        ) -> subprocess.CompletedProcess[str]:
    """Run a subprocess; on nonzero rc, print captured output and raise."""
    env: dict[str, str] | None = None
    if extra_env:
        env = os.environ.copy()
        env.update(extra_env)
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None,
                          env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        stderr_tail = '\n'.join((proc.stderr or '').splitlines()[-50:])
        stdout_tail = '\n'.join((proc.stdout or '').splitlines()[-20:])
        sys.stderr.write(f'[!] command failed (rc={proc.returncode}): {" ".join(cmd)}\n')
        if stderr_tail:
            sys.stderr.write(f'[!] stderr:\n{stderr_tail}\n')
        if stdout_tail:
            sys.stderr.write(f'[!] stdout:\n{stdout_tail}\n')
        raise Exception(fail_msg or f'command failed: {cmd[0]}')
    return proc


def resolve_executable(name: str) -> list[str] | None:
    """Resolve an executable name to argv prefix; check $PATH then .bat fallback."""
    direct = shutil.which(name)
    if direct is not None:
        return [direct]
    batch = get_path_to_batch(name)
    if batch is not None:
        return [batch]
    return None


def is_windows() -> bool:
    """Return True if running on Windows."""
    return platform.system() == "Windows"


def windows_hide_file(file_path: Path) -> None:
    """Set hidden attribute on a Windows path; return code ignored."""
    subprocess.run(["attrib", "+h", str(file_path)], capture_output=True)


def check_if_executable_exists_in_path(executable: str) -> bool:
    """Return True if executable resolves via shutil.which."""
    return shutil.which(executable) is not None


def get_executable_in_path(executable: str) -> str | None:
    """Return the resolved path for an executable on PATH, or None."""
    return shutil.which(executable)


def get_path_to_batch(batch: str) -> str | None:
    """Find a `<name>.bat` on PATH (Windows fallback for shutil.which gaps)."""
    path_env = os.environ.get('PATH', '')
    if not path_env:
        return None
    name = f'{batch}.bat'
    for path in path_env.split(os.pathsep):
        if not path:
            continue
        candidate = Path(path) / name
        if candidate.is_file():
            return str(candidate)
    return None


# === SECTION: Path helpers ===

def create_or_recreate_dir(dir_path: Path) -> None:
    """Wipe and recreate a directory (or replace a file at the same path)."""
    if dir_path.exists():
        if dir_path.is_dir():
            shutil.rmtree(dir_path)
        else:
            dir_path.unlink()
    dir_path.mkdir()
    if is_windows():
        windows_hide_file(dir_path)


@contextmanager
def working_tmp_dir(parent: Path) -> Generator[Path, None, None]:
    """Create the .xapktoapk tmp dir and clean it up on exit even when interrupted."""
    tmp = (parent / const_dir_tmp).absolute()
    create_or_recreate_dir(tmp)
    try:
        yield tmp
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)


def delete_file_if_exists(path_to_file: Path) -> None:
    """Remove a file if present; silent no-op otherwise."""
    if path_to_file.exists():
        path_to_file.unlink()


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
        raise Exception("no main APK found in xapk bundle")
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
    """Copy a single file, creating parent dirs as needed."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(src, dst)


def merge_apk_arch(dir_apk_main: Path, dir_apk_arch: Path) -> None:
    """Merge an architecture split's lib/ tree and apktool.yml entries into the main APK dir."""
    path_libs_src = dir_apk_arch / const_apk_dir_lib
    path_libs_dst = dir_apk_main / const_apk_dir_lib
    path_libs_dst.mkdir(exist_ok=True)

    for entry in path_libs_src.iterdir():
        shutil.copytree(entry, path_libs_dst / entry.name)

    cfg_src = parse_apktool_config(dir_apk_arch / const_apk_file_apktool_config)
    insert_new_lines_do_not_compress(dir_apk_main / const_apk_file_apktool_config,
                                     cfg_src.lines_do_not_compress)


def merge_apk_resources(dir_apk_main: Path, dir_apk_with_resources: Path) -> None:
    """Merge a resource split's res/ tree into the main APK dir; preserve existing files."""
    target_res_dir = dir_apk_main / 'res'
    res_dir = dir_apk_with_resources / 'res'
    if not res_dir.exists():
        return
    target_res_dir.mkdir(parents=True, exist_ok=True)

    for src, rel in iter_resource_files(res_dir, ('values', 'public.xml')):
        dst = target_res_dir / rel
        if dst.exists():
            continue
        copy_resource_file(src, dst)


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

    for src, rel in iter_resource_files(src_assets, None):
        dst = target_assets / rel
        if dst.exists():
            continue
        copy_resource_file(src, dst)

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

def unpack_apk(path_dir_tmp: Path, apk_file: str, number_current: int, number_total: int) -> None:
    """Unpack a single APK into the tmp dir via `apktool d -s`."""
    print(f'[*] unpacking {number_current} of {number_total}')
    apktool = resolve_executable('apktool')
    if apktool is None:
        raise Exception("apktool not found in PATH")
    # `--` sentinel prevents a malicious split filename like `-Dfoo.apk` from being parsed as a flag.
    run([*apktool, 'd', '-s', '--', apk_file], cwd=path_dir_tmp,
        fail_msg=f'failed to unpack {apk_file}')
    (path_dir_tmp / apk_file).unlink()


def pack_apk(path_dir_tmp: Path, main_apk_dir: Path) -> None:
    """Repack the merged main APK dir via `apktool b` into tmp/target.apk."""
    print('[*] repack apk')
    apktool = resolve_executable('apktool')
    if apktool is None:
        raise Exception("apktool not found in PATH")
    run([*apktool, 'b', '--', str(main_apk_dir)], cwd=path_dir_tmp,
        fail_msg=f'failed to pack {main_apk_dir.name}')
    built = main_apk_dir / 'dist' / f'{main_apk_dir.name}{const_ext_apk}'
    if not built.exists():
        raise Exception("result apk not found")
    target = path_dir_tmp / f'{const_file_target_file}{const_ext_apk}'
    if target.exists():
        target.unlink()
    shutil.copy(built, target)


def zipalign_apk(path_dir_tmp: Path) -> None:
    """Run `zipalign -p -f 4` on tmp/target.apk in-place."""
    print('[*] zipalign apk')
    target = path_dir_tmp / f'{const_file_target_file}{const_ext_apk}'
    if not target.exists():
        raise Exception("result apk not found")

    aligned = path_dir_tmp / f'aligned_{const_file_target_file}{const_ext_apk}'
    if aligned.exists():
        aligned.unlink()

    zipalign = resolve_executable('zipalign')
    if zipalign is None:
        raise Exception("zipalign not found in PATH")
    run([*zipalign, '-p', '-f', '4', str(target), str(aligned)],
        cwd=path_dir_tmp, fail_msg='failed to zipalign apk')
    if not aligned.exists():
        raise Exception("failed to zipalign apk (output missing)")
    target.unlink()
    shutil.move(aligned, target)


def build_single_apk(path_dir_tmp: Path, main_apk_dir: Path, sign: SignConfig | None) -> None:
    """Repack, zipalign, and optionally sign the merged APK."""
    pack_apk(path_dir_tmp, main_apk_dir)
    zipalign_apk(path_dir_tmp)
    if sign is not None:
        sign_apk(path_dir_tmp, sign)
    else:
        print('[*] skip signing apk')


# === SECTION: Sign + verify ===

def load_sign_env() -> SignConfig | None:
    """Read XAPKTOAPK_* env vars; return SignConfig if all four creds present, else None."""
    required = (const_env_keystore_file, const_env_keystore_password,
                const_env_key_alias, const_env_key_password)
    vals = {k: os.environ.get(k, '') for k in required}
    set_count = sum(1 for v in vals.values() if v)
    if set_count == 0:
        return None
    if set_count != len(required):
        missing = [k for k, v in vals.items() if not v]
        raise SystemExit(f"signing partially configured; missing: {', '.join(missing)}")

    keystore_file = Path(vals[const_env_keystore_file]).expanduser()
    if not keystore_file.is_file():
        raise SystemExit(f"{const_env_keystore_file} not found or not a file: {keystore_file}")

    min_sdk_raw = os.environ.get(const_env_min_sdk_version, '').strip()
    min_sdk: int | None = None
    if min_sdk_raw:
        if not min_sdk_raw.isdigit():
            raise SystemExit(f"{const_env_min_sdk_version} must be a positive integer")
        min_sdk = int(min_sdk_raw)

    return SignConfig(
        keystore_file=keystore_file,
        key_alias=vals[const_env_key_alias],
        min_sdk_version=min_sdk,
    )


def preflight_keystore(sign: SignConfig) -> None:
    """If keytool is available, validate keystore alias and warn on near-expiry certs."""
    keytool = resolve_executable('keytool')
    if keytool is None:
        return
    try:
        proc = subprocess.run(
            [
                *keytool,
                '-list', '-v',
                '-keystore', str(sign.keystore_file),
                '-alias', sign.key_alias,
                '-storepass:env', sign.keystore_password_env,
            ],
            capture_output=True, text=True, check=False,
        )
    except (OSError, FileNotFoundError) as e:
        sys.stderr.write(f'[!] keystore preflight skipped: {e}\n')
        return
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout or '')
        sys.stderr.write(proc.stderr or '')
        raise SystemExit('keystore preflight failed; check keystore path, alias, and password')

    m = re.search(r'Valid from:.*?until:\s*(.+)$', proc.stdout or '', re.MULTILINE)
    if not m:
        return
    expiry_str = m.group(1).strip()
    expiry: datetime.datetime | None = None
    # keytool emits locale-dependent dates; %Z may not yield a tz-aware datetime, so we tolerate naive comparison below.
    for fmt in ('%a %b %d %H:%M:%S %Z %Y', '%a %b %d %H:%M:%S %z %Y'):
        try:
            expiry = datetime.datetime.strptime(expiry_str, fmt)  # noqa: DTZ007
            break
        except ValueError:
            continue
    if expiry is None:
        return
    now = datetime.datetime.now(expiry.tzinfo) if expiry.tzinfo else datetime.datetime.now()  # noqa: DTZ005
    days_left = (expiry - now).days
    if days_left < 0:
        raise SystemExit(f'keystore certificate expired on {expiry_str}')
    if days_left < 90:
        print(f'[!] warning: keystore cert expires in {days_left} days ({expiry_str})')


def sign_apk(path_dir_tmp: Path, sign: SignConfig) -> None:
    """Sign tmp/target.apk via apksigner; verify v2+v3 schemes; print SHA-256."""
    target = path_dir_tmp / f'{const_file_target_file}{const_ext_apk}'
    if not target.exists():
        raise Exception("result apk not found")

    print('[*] resign apk')
    apksigner = resolve_executable('apksigner')
    if apksigner is None:
        raise Exception("apksigner not found in PATH")

    sign_cmd = [
        *apksigner,
        'sign',
        '--ks', str(sign.keystore_file),
        '--ks-pass', f'env:{sign.keystore_password_env}',
        '--ks-key-alias', sign.key_alias,
        '--key-pass', f'env:{sign.key_password_env}',
        '--v2-signing-enabled', 'true',
        '--v3-signing-enabled', 'true',
    ]
    if sign.min_sdk_version is not None:
        sign_cmd += ['--min-sdk-version', str(sign.min_sdk_version)]
    sign_cmd.append(str(target))

    run(sign_cmd, cwd=path_dir_tmp, fail_msg='failed to sign apk file')

    verify_proc = run([*apksigner, 'verify', '--verbose', '--print-certs', str(target)],
                      cwd=path_dir_tmp, fail_msg='apksigner verify failed')
    out = verify_proc.stdout or ''
    if 'Verified using v2 scheme (APK Signature Scheme v2): true' not in out \
            or 'Verified using v3 scheme (APK Signature Scheme v3): true' not in out:
        sys.stderr.write(out)
        raise Exception('apksigner verify did not confirm v2+v3 schemes')

    sha256: str | None = None
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith('Signer #1 certificate SHA-256 digest:'):
            sha256 = stripped.split(':', 1)[1].strip()
            break
    if sha256:
        print(f'[*] signed with SHA-256: {sha256}')
    else:
        print('[*] signature verified (v2+v3)')


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
    os.replace(tmp_path, path_manifest)


# === SECTION: Validation ===

def report_output_apk(apk_path: Path, expected_pkg: str, signed_expected: bool) -> None:
    """Inspect the final APK; print a one-line sanity report and any issues."""
    if not apk_path.is_file():
        return
    size_mb = apk_path.stat().st_size / (1024.0 * 1024.0)
    has_manifest = False
    has_dex = False
    has_signature = False
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
    except Exception as e:  # noqa: BLE001 - intentional: cosmetic post-build report; never block on inspection failure
        print(f'[!] could not inspect output apk: {e}')
        return

    issues: list[str] = []
    if not has_manifest:
        issues.append('missing AndroidManifest.xml')
    if not has_dex:
        issues.append('missing classes.dex')
    if signed_expected and not has_signature:
        issues.append('expected signature block missing')

    print(f'[*] result: {size_mb:.2f} MB, {entry_count} entries, '
          f'package={expected_pkg}, signed={has_signature}')
    if issues:
        print(f'[!] sanity issues: {"; ".join(issues)}')


# === SECTION: Phases ===

_ZIP_SYMLINK_MODE = 0o120000


def _safe_extract_zip(zip_path: Path, dest: Path) -> None:
    """Extract a zip into dest, rejecting absolute paths, `..` segments, and symlink members.

    Python's ZipFile.extractall sanitizes `..` and absolute paths since 3.6.2 but
    will still create symlink entries on POSIX, which can escape the destination.
    """
    with ZipFile(zip_path, 'r') as zf:
        for zinfo in zf.infolist():
            name = zinfo.filename
            parts = Path(name).parts
            if Path(name).is_absolute() or '..' in parts:
                raise Exception(f"refusing to extract unsafe zip entry: {name}")
            unix_mode = (zinfo.external_attr >> 16) & 0o170000
            if unix_mode == _ZIP_SYMLINK_MODE:
                raise Exception(f"refusing to extract symlink zip entry: {name}")
            zf.extract(zinfo, dest)


def phase_extract_xapk(xapk_abs_path: Path, tmp: Path) -> dict[str, Any]:
    """Copy the xapk into tmp, unzip it, parse manifest.json, return the parsed dict."""
    target_xapk = tmp / f'{const_file_target_file}{const_ext_xapk}'
    shutil.copy(xapk_abs_path, target_xapk)
    target_zip = tmp / f'{const_file_target_file}{const_ext_zip}'
    target_xapk.rename(target_zip)

    print('[*] unpacking xapk')
    _safe_extract_zip(target_zip, tmp)
    target_zip.unlink()

    manifest_path = tmp / const_file_xapk_manifest
    with manifest_path.open(encoding='UTF-8') as f:
        manifest: dict[str, Any] = json.load(f)
    return manifest


def phase_classify_splits(tmp: Path, package_name: str) -> list[ApkPart]:
    """Discover .apk files in tmp and classify each into an ApkPart by split type."""
    parts: list[ApkPart] = []
    for entry in tmp.iterdir():
        if entry.suffix != const_ext_apk or entry.is_dir():
            continue
        split_type = determine_split_type_by_apk_file_name(entry.name, package_name)
        if split_type is None:
            raise Exception(f'failed to determine split type of {entry.name}')
        parts.append(ApkPart(
            file_name=entry.name,
            file_path=entry.resolve(),
            dir_name=entry.stem,
            dir_path=(tmp / entry.stem).resolve(),
            split_type=split_type,
        ))
    print(f'[*] xapk file unpacked. {len(parts)} parts discovered')
    return parts


def phase_unpack_splits(tmp: Path, parts: list[ApkPart]) -> None:
    """Run apktool d -s on every split; fail-fast on any error (corrupt base = unrecoverable)."""
    total = len(parts)
    for index, part in enumerate(parts):
        unpack_apk(tmp, part.file_name, index + 1, total)


def _safe_merge(part: ApkPart, phase: str, fn: Callable[[], None],
                failures: list[StepFailure]) -> None:
    """Run fn(); append a StepFailure to failures on any Exception."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001 - merge step has many failure modes (apktool yml shape, missing dirs, copy errors); collect-and-continue is the contract
        failures.append(StepFailure(apk_file=part.file_name, phase=phase, error=str(e)))


def phase_merge_splits(parts: list[ApkPart]) -> tuple[ApkPart, list[StepFailure]]:
    """Merge arch + dpi + locale + assetpack splits into the main APK dir; collect non-fatal failures."""
    main = get_main_apk(parts)
    arch_parts = get_apks_of_type(parts, const_split_apk_type_arch)
    dpi_parts = get_apks_of_type(parts, const_split_apk_type_dpi)
    locale_parts = get_apks_of_type(parts, const_split_apk_type_locale)
    assetpack_parts = get_apks_of_type(parts, const_split_apk_type_assetpack)

    failures: list[StepFailure] = []
    for p in arch_parts:
        _safe_merge(p, 'merge_arch',
                    partial(merge_apk_arch, main.dir_path, p.dir_path), failures)
    for p in prioritize_dpi_apk_list(dpi_parts):
        _safe_merge(p, 'merge_resources',
                    partial(merge_apk_resources, main.dir_path, p.dir_path), failures)
    for p in locale_parts:
        _safe_merge(p, 'merge_resources',
                    partial(merge_apk_resources, main.dir_path, p.dir_path), failures)
        _safe_merge(p, 'merge_assets',
                    partial(merge_apk_assets, main.dir_path, p.dir_path), failures)
    for p in assetpack_parts:
        _safe_merge(p, 'merge_assets',
                    partial(merge_apk_assets, main.dir_path, p.dir_path), failures)

    return main, failures


def phase_finalize_main_apk(main: ApkPart) -> None:
    """Strip leftover signature files and rewrite AndroidManifest for the merged APK."""
    delete_signature_related_files(main.dir_path)
    update_main_manifest_file(main.dir_path)


def phase_build_and_sign(tmp: Path, main: ApkPart, sign: SignConfig | None) -> None:
    """Repack, zipalign, and (optionally) sign the merged APK in tmp."""
    build_single_apk(tmp, main.dir_path, sign)


# === SECTION: CLI entry ===

def copy_single_apk_to_working_dir(tmp: Path, working_dir: Path, target_name: str) -> Path:
    """Copy tmp/target.apk to <working_dir>/<target_name>.apk; return the destination path."""
    src = tmp / f'{const_file_target_file}{const_ext_apk}'
    if not src.is_file():
        raise Exception("result apk file not found")
    dst = working_dir / f'{target_name}{const_ext_apk}'
    if dst.is_dir():
        raise Exception(f"refusing to overwrite directory at {dst}")
    if dst.exists():
        dst.unlink()
    shutil.copy(src, dst)
    return dst


def _verify_required_tools(should_sign: bool) -> None:
    """Ensure apktool, zipalign, and (optionally) apksigner are available; exit if not."""
    for tool in ('apktool', 'zipalign'):
        if not check_if_executable_exists_in_path(tool) and get_path_to_batch(tool) is None:
            print(f"executable {tool} not found in $PATH, please install it before running xapktoapk")
            sys.exit(-2)
    if should_sign and not check_if_executable_exists_in_path('apksigner') and get_path_to_batch('apksigner') is None:
        print("executable apksigner not found in $PATH, please install it before running xapktoapk")
        sys.exit(-2)


def _print_merge_failures(failures: list[StepFailure]) -> None:
    """Print a one-line summary plus per-failure detail to stderr."""
    sys.stderr.write(f'[!] {len(failures)} merge step(s) failed:\n')
    for f in failures:
        sys.stderr.write(f'    - {f.apk_file} ({f.phase}): {f.error}\n')


def main() -> None:
    """CLI entry: validate args, run all phases, write the final apk next to the source xapk."""
    if not check_sys_args():
        print_help()
        sys.exit(-1)

    sign_config = load_sign_env()
    _verify_required_tools(should_sign=sign_config is not None)
    if sign_config is not None:
        preflight_keystore(sign_config)

    xapk_abs = get_param_xapk_abs_path()
    original_stem, _ = file_split_name_and_extension(get_param_xapk_file_name())

    print('[*] start')
    cwd = Path.cwd().resolve()

    with working_tmp_dir(cwd) as tmp:
        manifest = phase_extract_xapk(xapk_abs, tmp)
        package_name = manifest[const_file_xapk_manifest_key_package_name]

        parts = phase_classify_splits(tmp, package_name)
        phase_unpack_splits(tmp, parts)

        main_part, failures = phase_merge_splits(parts)
        if failures:
            _print_merge_failures(failures)
            sys.exit(3)

        phase_finalize_main_apk(main_part)
        phase_build_and_sign(tmp, main_part, sign_config)

        final_apk = copy_single_apk_to_working_dir(tmp, cwd, original_stem)
        report_output_apk(final_apk, package_name, sign_config is not None)

    print('[*] complete')


if __name__ == '__main__':
    main()
