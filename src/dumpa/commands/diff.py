"""`dumpa diff` — what changed between two apps (or two workspaces)."""

from __future__ import annotations

from pathlib import Path

from dumpa.commands.analyze import report_for_input
from dumpa.core.diff import diff_reports, render_diff


def diff(old: Path, new: Path) -> None:
    """Compare two APK/XAPK inputs (or workspace dirs) and print the finding diff."""
    old_report = report_for_input(old)
    new_report = report_for_input(new)
    text = render_diff(old.name, new.name, diff_reports(old_report, new_report))
    print(text, end="")
