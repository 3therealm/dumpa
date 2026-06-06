"""Repack, zipalign, and sign the merged APK."""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.convert.models import (
    const_ext_apk,
    const_file_target_file,
    const_split_apk_type_arch,
    const_split_apk_type_assetpack,
    const_split_apk_type_dpi,
    const_split_apk_type_locale,
    const_split_apk_type_main,
)
from dumpa.core.config import (
    SigningConfig,
    const_default_validation_timeout,
    const_env_validation_timeout,
)
from dumpa.core.env import env_positive_int
from dumpa.core.errors import XapkToApkError
from dumpa.core.tools import ResolvedTool, ToolRegistry
from dumpa.tools import apksigner, apktool, zipalign

logger = logging.getLogger("dumpa")

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


def build_single_apk(registry: ToolRegistry, path_dir_tmp: Path, main_apk_dir: Path,
                     sign: SigningConfig | None) -> None:
    """Repack, zipalign, and optionally sign the merged APK."""
    pack_apk(registry.resolve('apktool'), path_dir_tmp, main_apk_dir)
    zipalign_apk(registry.resolve('zipalign'), path_dir_tmp)
    if sign is not None:
        sign_apk(registry.resolve('apksigner'), path_dir_tmp, sign)
    else:
        logger.info("skip signing apk")


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
        env_positive_int(const_env_validation_timeout, const_default_validation_timeout),
    )
    info = apksigner.parse_verify_output(out)
    if 'v2' not in info.schemes or 'v3' not in info.schemes:
        logger.error("%s", out)
        raise XapkToApkError('apksigner verify did not confirm v2+v3 schemes')

    schemes = '+'.join(info.schemes)
    if info.cert_sha256:
        logger.info("signed (%s); cert SHA-256: %s", schemes, info.cert_sha256)
    else:
        logger.info("signature verified (%s)", schemes)
