"""input_type classification and arch-split -> ABI mapping."""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.commands.analyze import input_type
from dumpa.commands.info import _abi_of_arch_split
from dumpa.core.errors import DumpaError


def test_input_type_apk() -> None:
    assert input_type(Path("game.apk")) == "apk"
    assert input_type(Path("GAME.APK")) == "apk"


def test_input_type_xapk() -> None:
    assert input_type(Path("game.xapk")) == "xapk"


def test_input_type_rejects_other() -> None:
    with pytest.raises(DumpaError, match=r"expected a \.apk or \.xapk"):
        input_type(Path("game.zip"))


def test_abi_mapping_keeps_x86_64() -> None:
    assert _abi_of_arch_split("config.x86_64.apk") == "x86_64"


def test_abi_mapping_dashes_arm() -> None:
    assert _abi_of_arch_split("config.arm64_v8a.apk") == "arm64-v8a"
    assert _abi_of_arch_split("config.armeabi_v7a.apk") == "armeabi-v7a"


def test_abi_mapping_no_config_part() -> None:
    assert _abi_of_arch_split("base.apk") is None
