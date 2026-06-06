"""`dumpa export` — render a workspace's analysis report in a chosen format.

Reads `<workspace>/reports/report.json` (rebuilding it from the workspace if it is
missing) and emits JSON or Markdown to stdout or a file. CSV/HTML/SARIF are not yet
supported — CSV needs the tracker/domain lists that arrive with the Phase 5 scanners.
"""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.commands.analyze import const_file_report_json
from dumpa.core.config import load_config
from dumpa.core.errors import DumpaError
from dumpa.core.report import Report, read_json, render_markdown, to_json
from dumpa.core.tools import build_default_registry
from dumpa.core.workspace import Workspace
from dumpa.reporting import build_report

logger = logging.getLogger("dumpa")

const_export_formats = ("json", "md", "markdown")
_NOT_YET = ("csv", "html", "sarif")


def _load_report(workspace: Path) -> Report:
    """Load the workspace report, rebuilding from the workspace if the JSON is absent."""
    ws = Workspace(root=workspace.resolve())
    if not ws.root.is_dir():
        raise DumpaError(f"workspace not found: {ws.root}")
    report = read_json(ws.reports_dir / const_file_report_json)
    if report is not None:
        return report
    if ws.read_meta() is None:
        raise DumpaError(f"{ws.root} is not a dumpa workspace; run `dumpa analyze` first")
    registry = build_default_registry(load_config().tool_paths)
    return build_report(registry, ws)


def export(workspace: Path, *, fmt: str, out: Path | None = None) -> None:
    """Render the report for a workspace as JSON or Markdown."""
    name = fmt.lower()
    if name in _NOT_YET:
        raise DumpaError(f"export format {name!r} is not supported yet (try json or md)")
    if name not in const_export_formats:
        raise DumpaError(f"unknown export format {fmt!r} (expected json or md)")

    report = _load_report(workspace)
    text = to_json(report) if name == "json" else render_markdown(report)

    if out is not None:
        out.write_text(text, encoding="UTF-8")
        logger.info("wrote %s report: %s", name, out)
    else:
        print(text, end="" if text.endswith("\n") else "\n")
