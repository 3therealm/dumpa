"""ABI preference: pick one ABI when an apk ships several.

A multi-ABI apk carries the same native code per architecture; analysis tools that are
expensive per library (il2cpp dump, radare2 region scan) run against one preferred ABI
rather than all of them. This is the single source of that preference order.
"""

from __future__ import annotations

from collections.abc import Iterable

# Preference when an apk ships multiple ABIs and the user did not pin one.
ARCH_PREFERENCE = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")


def select_primary_abi(abis: Iterable[str]) -> str | None:
    """Pick one ABI by preference order; fall back to the first given; None if empty."""
    present = list(abis)
    if not present:
        return None
    available = set(present)
    for arch in ARCH_PREFERENCE:
        if arch in available:
            return arch
    return present[0]
