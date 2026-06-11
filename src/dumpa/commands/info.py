"""`dumpa info` — fast triage facts for an APK/XAPK, no deep analysis.

One `aapt dump badging` plus one `apksigner verify` give package, version, SDK
levels, ABIs, permission count, and signer cert/schemes. No apktool decode, no
persistent workspace. For an .xapk the base/main split is probed and ABIs are read
from the arch split names.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from dumpa.commands.analyze import input_type
from dumpa.convert.classify import get_apks_of_type, get_main_apk
from dumpa.convert.models import (
    const_file_xapk_manifest,
    const_file_xapk_manifest_key_package_name,
    const_split_apk_type_arch,
)
from dumpa.convert.pipeline import load_xapk_manifest, phase_classify_splits
from dumpa.core.archive import safe_extract_zip
from dumpa.core.config import (
    const_default_validation_timeout,
    const_env_validation_timeout,
    load_config,
)
from dumpa.core.env import env_positive_int
from dumpa.core.errors import ToolExecutionError, ToolNotFoundError
from dumpa.core.fs import working_tmp_dir
from dumpa.core.rules import probe_engine_from_names
from dumpa.core.tools import ToolRegistry, build_default_registry
from dumpa.tools import aapt, apksigner

# Arch split config names use underscores; map to canonical ABI labels (x86_64 keeps it).
_ARCH_SPLIT_TO_ABI = {
    'arm64_v8a': 'arm64-v8a',
    'armeabi_v7a': 'armeabi-v7a',
    'armeabi': 'armeabi',
    'x86': 'x86',
    'x86_64': 'x86_64',
}


def _validation_timeout() -> int:
    return env_positive_int(const_env_validation_timeout, const_default_validation_timeout)


def _abi_of_arch_split(file_name: str) -> str | None:
    """config.<arch>.apk -> canonical ABI label, or None if the name has no config part."""
    parts = Path(file_name).stem.split('.')
    if len(parts) < 2:
        return None
    name = parts[1]
    return _ARCH_SPLIT_TO_ABI.get(name, name.replace('_', '-'))


def _xapk_probe_target(xapk_abs: Path, tmp: Path) -> tuple[Path, tuple[str, ...]]:
    """Extract the xapk, return (base/main apk path, ABIs from arch splits)."""
    safe_extract_zip(xapk_abs, tmp)
    manifest = load_xapk_manifest(tmp / const_file_xapk_manifest)
    package = manifest[const_file_xapk_manifest_key_package_name]
    parts = phase_classify_splits(tmp, package)
    main = get_main_apk(parts)
    abis = tuple(
        abi for p in get_apks_of_type(parts, const_split_apk_type_arch)
        if (abi := _abi_of_arch_split(p.file_name)) is not None
    )
    return main.file_path, abis


def _read_signer(registry: ToolRegistry, apk: Path) -> apksigner.SignerInfo | None:
    """Read signer facts; None when apksigner is absent or the apk is unsigned."""
    try:
        tool = registry.resolve('apksigner')
    except ToolNotFoundError:
        return None
    try:
        out = apksigner.verify(tool, apk, _validation_timeout(), quiet=True)
    except ToolExecutionError:
        return None  # unsigned apks make `verify` exit non-zero
    return apksigner.parse_verify_output(out)


def _read_badging(registry: ToolRegistry, apk: Path) -> aapt.BadgingInfo:
    try:
        tool = registry.resolve('aapt')
    except ToolNotFoundError:
        return aapt.BadgingInfo()
    return aapt.read_badging(tool, apk, _validation_timeout())


def _probe_engine(apk: Path) -> str | None:
    """Detect the game engine from the apk's zip entry names (no extraction)."""
    try:
        with zipfile.ZipFile(apk) as zf:
            return probe_engine_from_names(zf.namelist())
    except (OSError, zipfile.BadZipFile):
        return None


def _print_info(input_abs: Path, in_type: str, badging: aapt.BadgingInfo,
                signer: apksigner.SignerInfo | None, abis: tuple[str, ...],
                engine: str | None) -> None:
    size_mb = input_abs.stat().st_size / (1024.0 * 1024.0)
    version = badging.version_name or '?'
    if badging.version_code:
        version += f' ({badging.version_code})'
    rows = [
        ("file", input_abs.name),
        ("type", in_type),
        ("size", f"{size_mb:.2f} MB"),
        ("package", badging.package or 'unknown'),
        ("version", version),
        ("engine", engine or 'unknown'),
        ("minSdk", badging.min_sdk or '?'),
        ("targetSdk", badging.target_sdk or '?'),
        ("ABIs", ", ".join(abis) if abis else 'none'),
        ("permissions", str(badging.permission_count)),
        ("signer cert", signer.cert_sha256 if signer and signer.cert_sha256 else 'unsigned/unknown'),
        ("schemes", '+'.join(signer.schemes) if signer and signer.schemes else 'none'),
        ("debug cert", ('yes' if signer.is_debug else 'no') if signer else '?'),
    ]
    width = max(len(k) for k, _ in rows)
    for key, value in rows:
        print(f"{key.ljust(width)}  {value}")


def info(input_file: Path) -> None:
    """Print fast triage facts for an APK or XAPK."""
    config = load_config()
    registry = build_default_registry(config.tool_paths)
    input_abs = input_file.resolve()
    in_type = input_type(input_abs)

    with working_tmp_dir(input_abs.parent) as tmp:
        if in_type == "xapk":
            probe_apk, abis_override = _xapk_probe_target(input_abs, tmp)
        else:
            probe_apk, abis_override = input_abs, None
        badging = _read_badging(registry, probe_apk)
        signer = _read_signer(registry, probe_apk)
        engine = _probe_engine(probe_apk)

    abis = abis_override if abis_override is not None else badging.abis
    _print_info(input_abs, in_type, badging, signer, abis, engine)
