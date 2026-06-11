"""Primary-ABI selection: preference order, fallback, and empty handling."""

from __future__ import annotations

from dumpa.core.abi import select_primary_abi


def test_prefers_arm64() -> None:
    assert select_primary_abi(["x86", "arm64-v8a", "armeabi-v7a"]) == "arm64-v8a"


def test_preference_order_honored() -> None:
    assert select_primary_abi(["x86_64", "x86"]) == "x86_64"
    assert select_primary_abi(["x86", "armeabi-v7a"]) == "armeabi-v7a"


def test_single_abi() -> None:
    assert select_primary_abi(["x86"]) == "x86"


def test_unknown_abi_falls_back_to_first() -> None:
    assert select_primary_abi(["mips", "riscv64"]) == "mips"


def test_empty_is_none() -> None:
    assert select_primary_abi([]) is None
