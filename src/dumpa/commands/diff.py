"""`dumpa diff` — what changed between two apps (or two workspaces)."""

from __future__ import annotations

from pathlib import Path

from dumpa.commands.analyze import open_for_diff
from dumpa.core.diff import (
    diff_native_symbols,
    diff_reports,
    diff_unity_methods,
    render_diff,
    render_native_symbol_diff,
    render_unity_method_diff,
)

const_engine_unity = "Unity"


def diff(old: Path, new: Path) -> None:
    """Compare two APK/XAPK inputs (or workspace dirs) and print the finding diff.

    Holds both workspaces open so the native-symbol and Unity-method diffs can read
    workspace sidecars (dumps/native/*.json, dumps/dump.cs) that are not in the report.
    """
    with open_for_diff(old) as (old_ws, old_report), \
            open_for_diff(new) as (new_ws, new_report):
        sections = [render_diff(old.name, new.name, diff_reports(old_report, new_report))]
        sections.append(render_native_symbol_diff(diff_native_symbols(old_ws, new_ws)))
        if new_report.facts.engine == const_engine_unity:
            sections.append(render_unity_method_diff(diff_unity_methods(old_ws, new_ws)))
    text = "\n".join(s for s in sections if s).rstrip() + "\n"
    print(text, end="")
