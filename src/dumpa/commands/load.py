"""`dumpa load` — analyze a directory of APK/XAPK files into one combined summary."""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.commands.analyze import report_for_input
from dumpa.core.errors import DumpaError

logger = logging.getLogger("dumpa")

const_inputs_suffixes = (".apk", ".xapk", ".apks")


def _counts(kind: str, findings_kinds: list[str]) -> int:
    return sum(1 for k in findings_kinds if k == kind)


def load(directory: Path) -> None:
    """Analyze every .apk/.xapk/.apks in a directory and print one summary row per file."""
    root = directory.resolve()
    if not root.is_dir():
        raise DumpaError(f"not a directory: {root}")
    inputs = sorted(p for p in root.iterdir() if p.suffix.lower() in const_inputs_suffixes)
    if not inputs:
        print("no .apk/.xapk/.apks files found")
        return

    print(f"{'file':40} {'package':32} {'engine':10} trk prot sec")
    for path in inputs:
        try:
            report = report_for_input(path)
        except (DumpaError, OSError) as e:
            print(f"{path.name:40} ERROR: {e}")
            continue
        kinds = [f.kind for f in report.findings]
        print(f"{path.name:40.40} {(report.facts.package or '?'):32.32} "
              f"{(report.facts.engine or '-'):10.10} "
              f"{_counts('tracker', kinds):3} {_counts('protection', kinds):4} "
              f"{_counts('secret', kinds):3}")
