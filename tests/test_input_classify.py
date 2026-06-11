"""input_type classification and arch-split -> ABI mapping."""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.commands.analyze import input_type
from dumpa.commands.info import _abi_of_arch_split
from dumpa.convert.classify import config_token, determine_split_type_by_apk_file_name
from dumpa.core.errors import DumpaError


def test_input_type_apk() -> None:
    assert input_type(Path("game.apk")) == "apk"
    assert input_type(Path("GAME.APK")) == "apk"


def test_input_type_xapk() -> None:
    assert input_type(Path("game.xapk")) == "xapk"


def test_input_type_apks() -> None:
    assert input_type(Path("game.apks")) == "apks"
    assert input_type(Path("GAME.APKS")) == "apks"


def test_input_type_rejects_other() -> None:
    with pytest.raises(DumpaError, match=r"expected a \.apk, \.xapk, or \.apks"):
        input_type(Path("game.zip"))


def test_abi_mapping_keeps_x86_64() -> None:
    assert _abi_of_arch_split("config.x86_64.apk") == "x86_64"


def test_abi_mapping_dashes_arm() -> None:
    assert _abi_of_arch_split("config.arm64_v8a.apk") == "arm64-v8a"
    assert _abi_of_arch_split("config.armeabi_v7a.apk") == "armeabi-v7a"


def test_abi_mapping_bundletool_naming() -> None:
    # bundletool `base-<token>.apk` and SAI `split_config.<token>.apk` resolve too.
    assert _abi_of_arch_split("base-arm64_v8a.apk") == "arm64-v8a"
    assert _abi_of_arch_split("split_config.x86_64.apk") == "x86_64"


def test_abi_mapping_no_config_part() -> None:
    assert _abi_of_arch_split("base.apk") is None
    assert _abi_of_arch_split("base-master.apk") is None


# --- split classification across XAPK / bundletool / SAI naming --------------

@pytest.mark.parametrize(("name", "expected"), [
    # XAPK-style (config.<token>.apk)
    ("config.arm64_v8a.apk", "arch"),
    ("config.xxhdpi.apk", "dpi"),
    ("config.en.apk", "locale"),
    # bundletool-style (base-<token>.apk)
    ("base-arm64_v8a.apk", "arch"),
    ("base-xxhdpi.apk", "dpi"),
    ("base-en.apk", "locale"),
    # SAI-style (split_config.<token>.apk)
    ("split_config.x86_64.apk", "arch"),
    ("split_config.tvdpi.apk", "dpi"),
    # mains
    ("base.apk", "main"),
    ("base-master.apk", "main"),
    # asset packs and dynamic-feature masters
    ("media.assetpack.apk", "assetpack"),
    ("myfeature-master.apk", "locale"),
])
def test_determine_split_type(name: str, expected: str) -> None:
    # Package name only matters for the `<pkg>.apk` main convention; pass empty here.
    assert determine_split_type_by_apk_file_name(name, "") == expected


def test_determine_split_type_pkg_named_main() -> None:
    assert determine_split_type_by_apk_file_name("com.x.apk", "com.x") == "main"


def test_config_token_none_for_non_config() -> None:
    assert config_token("base.apk") is None
    assert config_token("base-master.apk") is None
    assert config_token("toc.pb") is None
