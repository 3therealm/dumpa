"""zipalign adapter: align an APK and verify alignment."""

from __future__ import annotations

from pathlib import Path

from dumpa.core.process import run
from dumpa.core.tools import ResolvedTool


def align(tool: ResolvedTool, src: Path, dst: Path) -> None:
    """`zipalign -p -f 4 src dst` (page-align .so entries, overwrite dst)."""
    run(tool.argv('-p', '-f', '4', str(src), str(dst)), fail_msg='failed to zipalign apk')


def check(tool: ResolvedTool, apk: Path, timeout: int) -> None:
    """`zipalign -c -v 4` — raises ToolExecutionError if alignment is broken."""
    run(tool.argv('-c', '-v', '4', str(apk)), timeout=timeout,
        fail_msg='zipalign verify failed (alignment broken)')
