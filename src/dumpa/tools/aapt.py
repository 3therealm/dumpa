"""aapt/aapt2 adapter: read package badging from an APK."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from dumpa.core.errors import ToolExecutionError
from dumpa.core.process import run
from dumpa.core.tools import ResolvedTool

_BADGING_PATTERN = re.compile(
    r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'"
)
_MIN_SDK_RE = re.compile(r"^sdkVersion:'([^']*)'", re.MULTILINE)
_TARGET_SDK_RE = re.compile(r"^targetSdkVersion:'([^']*)'", re.MULTILINE)
_PERMISSION_RE = re.compile(r"^uses-permission(?:-sdk-\d+)?: name='([^']+)'", re.MULTILINE)
_NATIVE_CODE_RE = re.compile(r"^(?:alt-)?native-code: (.+)$", re.MULTILINE)
_QUOTED_RE = re.compile(r"'([^']+)'")


@dataclass(frozen=True)
class BadgingInfo:
    """Triage facts parsed from `aapt dump badging`. Fields are None/empty when absent."""
    package: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    abis: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()

    @property
    def permission_count(self) -> int:
        return len(self.permissions)


def badging(tool: ResolvedTool, apk: Path, timeout: int) -> tuple[str | None, str | None, str | None]:
    """Run `dump badging`; return (package, versionCode, versionName).

    Returns (None, None, None) if the invocation fails or output is unparseable —
    this inspection is opportunistic, never blocking.
    """
    try:
        proc = run(tool.argv('dump', 'badging', str(apk)), timeout=timeout, capture_stdout=True)
    except ToolExecutionError:
        return (None, None, None)
    m = _BADGING_PATTERN.search(proc.stdout or '')
    if not m:
        return (None, None, None)
    return (m.group(1), m.group(2), m.group(3))


def parse_badging(text: str) -> BadgingInfo:
    """Parse `aapt dump badging` output into a BadgingInfo (pure; tolerant of missing fields)."""
    pkg = _BADGING_PATTERN.search(text)
    abis: tuple[str, ...] = ()
    native = _NATIVE_CODE_RE.search(text)
    if native:
        abis = tuple(_QUOTED_RE.findall(native.group(1)))
    return BadgingInfo(
        package=pkg.group(1) if pkg else None,
        version_code=pkg.group(2) if pkg else None,
        version_name=pkg.group(3) if pkg else None,
        min_sdk=(m.group(1) if (m := _MIN_SDK_RE.search(text)) else None),
        target_sdk=(m.group(1) if (m := _TARGET_SDK_RE.search(text)) else None),
        abis=abis,
        permissions=tuple(_PERMISSION_RE.findall(text)),
    )


def read_badging(tool: ResolvedTool, apk: Path, timeout: int) -> BadgingInfo:
    """Run `dump badging` and parse the full triage view; empty BadgingInfo on failure.

    Opportunistic: a parse failure on an odd apk is logged at debug, not error.
    """
    try:
        proc = run(tool.argv('dump', 'badging', str(apk)), timeout=timeout,
                   capture_stdout=True, quiet=True)
    except ToolExecutionError:
        return BadgingInfo()
    return parse_badging(proc.stdout or '')
