"""aapt/aapt2 adapter: read package badging from an APK."""

from __future__ import annotations

import re
from pathlib import Path

from dumpa.core.errors import ToolExecutionError
from dumpa.core.process import run
from dumpa.core.tools import ResolvedTool

_BADGING_PATTERN = re.compile(
    r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'"
)


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
