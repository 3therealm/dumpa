"""`dumpa export` — render a workspace's analysis report in a chosen format.

Reads `<workspace>/reports/report.json` (rebuilding it from the workspace if it is
missing) and emits JSON, Markdown, or a domain blocklist (Pi-hole-style `hosts` or
AdGuard `||host^`) to stdout or a file. CSV/HTML/SARIF are not yet supported.
"""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.commands.analyze import const_file_report_json
from dumpa.core.config import load_config
from dumpa.core.errors import DumpaError
from dumpa.core.report import Report, read_json, render_blocklist, render_markdown, to_json
from dumpa.core.tools import build_default_registry
from dumpa.core.workspace import Workspace
from dumpa.reporting import build_report

logger = logging.getLogger("dumpa")

const_export_formats = ("json", "md", "markdown", "hosts", "adguard")
_NOT_YET = ("csv", "html", "sarif")


def _render(report: Report, name: str) -> str:
    if name == "json":
        return to_json(report)
    if name in ("hosts", "adguard"):
        return render_blocklist(report, name)
    return render_markdown(report)


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
        raise DumpaError(f"export format {name!r} is not supported yet")
    if name not in const_export_formats:
        raise DumpaError(f"unknown export format {fmt!r} (expected json, md, hosts, or adguard)")

    report = _load_report(workspace)
    text = _render(report, name)

    if out is not None:
        out.write_text(text, encoding="UTF-8")
        logger.info("wrote %s report: %s", name, out)
    else:
        print(text, end="" if text.endswith("\n") else "\n")
