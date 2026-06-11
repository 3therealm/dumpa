"""`dumpa scan-trackers` / `dumpa scan-protections` — focused, report-less scans.

Tracker and protection detection also runs inside `analyze`, but these commands give
a fast, single-purpose view: run just the one scanner (plus the shared enrichment
tail, so findings still carry dex/RVA/resource backfill and — for trackers —
owner/domain attribution) and print one finding per line. Like `scan-native`, this is
analysis-only: it does not persist a report (`analyze` owns the report).

Accepts a populated workspace directory or an `.apk`/`.xapk` (extracted into a
throwaway workspace for the run), via the shared `open_target` opener.
"""

from __future__ import annotations

import logging
from pathlib import Path

import typer

from dumpa.commands.base import open_target
from dumpa.core.config import load_config
from dumpa.core.report import Finding
from dumpa.core.tools import build_default_registry
from dumpa.scanners import run_selected

logger = logging.getLogger("dumpa")


def _location_summary(finding: Finding) -> str:
    """A compact pointer to the first location (path[+offset], dex class, or domain)."""
    for loc in finding.locations:
        if loc.file_path:
            return f"{loc.file_path}+0x{loc.file_offset:x}" if loc.file_offset else loc.file_path
        if loc.dex_class:
            return loc.dex_class
        if loc.domain:
            return loc.domain
    return ""


def _print(findings: list[Finding], kind: str, salient: str) -> None:
    """Print one line per finding of `kind`: subject · confidence · salient attr · location."""
    rows = [
        (f.subject, f.confidence.value, f.attributes.get(salient, ""), _location_summary(f))
        for f in findings if f.kind == kind
    ]
    if not rows:
        typer.echo(f"no {kind} findings")
        return
    subj_w = max(len(r[0]) for r in rows)
    conf_w = max(len(r[1]) for r in rows)
    attr_w = max(len(r[2]) for r in rows)
    for subject, conf, attr, loc in rows:
        typer.echo(f"{subject.ljust(subj_w)}  {conf.ljust(conf_w)}  "
                   f"{attr.ljust(attr_w)}  {loc}")


def _scan(target: Path, scanner: str, kind: str, salient: str) -> None:
    config = load_config()
    registry = build_default_registry(config.tool_paths)
    with open_target(registry, target) as ws:
        findings = run_selected(ws, [scanner], registry=registry)
        _print(findings, kind, salient)


def scan_trackers(target: Path) -> None:
    """Scan a workspace/apk for trackers and print one finding per line."""
    _scan(target, "tracker", "tracker", "owner")


def scan_protections(target: Path) -> None:
    """Scan a workspace/apk for protections and print one finding per line."""
    _scan(target, "protection", "protection", "category")
