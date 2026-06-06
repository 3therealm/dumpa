"""Post-build sanity checks on the final APK (CRC, alignment, manifest, badging)."""

from __future__ import annotations

import logging
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from dumpa.core.config import const_default_validation_timeout, const_env_validation_timeout
from dumpa.core.env import env_positive_int
from dumpa.core.errors import ToolExecutionError, ToolNotFoundError
from dumpa.core.tools import ToolRegistry
from dumpa.tools import aapt, zipalign

logger = logging.getLogger("dumpa")


def _parse_aapt_badging(registry: ToolRegistry, apk_path: Path) -> tuple[str | None, str | None, str | None]:
    """Read package badging from apk_path via aapt; (None, None, None) if unavailable."""
    try:
        tool = registry.resolve('aapt')
    except ToolNotFoundError:
        return (None, None, None)
    return aapt.badging(
        tool, apk_path,
        env_positive_int(const_env_validation_timeout, const_default_validation_timeout),
    )


def verify_zipalign(registry: ToolRegistry, apk_path: Path) -> str | None:
    """Verify 4-byte alignment via zipalign; returns error message or None."""
    try:
        tool = registry.resolve('zipalign')
    except ToolNotFoundError:
        return None
    try:
        zipalign.check(
            tool, apk_path,
            env_positive_int(const_env_validation_timeout, const_default_validation_timeout),
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


def report_output_apk(registry: ToolRegistry, apk_path: Path, expected_pkg: str,
                      signed_expected: bool, input_size_bytes: int) -> None:
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

    align_err = verify_zipalign(registry, apk_path)
    if align_err:
        issues.append(align_err)

    aapt_pkg, _, aapt_ver = _parse_aapt_badging(registry, apk_path)
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
