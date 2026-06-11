"""Resource-table scanner: enumerate `resources.arsc` (strings, layouts, raw, blobs).

Parses the binary resource table with the zero-dep `core.arsc` parser and, per package,
writes a sidecar under `dumps/resources/` (type counts + named string entries) and emits
one compact `resource-table` `Finding`. The report stays small (counts only); the detail
lives in the sidecar, which also feeds the xref RESOURCE layer and the resource-name
attribution pass. Absent or malformed `resources.arsc` -> no findings.
"""

from __future__ import annotations

import json
import logging

from dumpa.core.arsc import ArscPackage, parse_arsc_file
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_resource_table_kind = "resource-table"
const_arsc_name = "resources.arsc"
_MAX_TYPES_IN_ATTR = 16


def _write_sidecar(ws: Workspace, pkg: ArscPackage) -> str | None:
    """Write per-package type counts + named string entries to dumps/resources/."""
    safe = pkg.name or f"pkg{pkg.id:x}"
    sidecar = ws.resources_dir / f"{safe}.json"
    payload = {
        "package": pkg.name,
        "id": pkg.id,
        "type_counts": pkg.type_counts(),
        "strings": [{"type": e.type_name, "name": e.name, "value": e.value,
                     **({"config": e.config} if e.config else {})}
                    for e in pkg.entries if e.value is not None],
    }
    try:
        ws.resources_dir.mkdir(parents=True, exist_ok=True)
        with sidecar.open("w", encoding="UTF-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError:
        logger.warning("could not write resources sidecar for %s", pkg.name, exc_info=True)
        return None
    return sidecar.relative_to(ws.root).as_posix()


def scan(ws: Workspace) -> list[Finding]:
    """Enumerate resources.arsc; one resource-table finding per package."""
    arsc = ws.extracted_dir / const_arsc_name
    if not arsc.is_file():
        return []
    table = parse_arsc_file(arsc)
    if table is None or not table.packages:
        return []

    findings: list[Finding] = []
    for pkg in table.packages:
        counts = pkg.type_counts()
        if not counts:
            continue
        string_count = sum(1 for e in pkg.entries if e.value is not None)
        top = ", ".join(f"{name}={n}" for name, n in
                        sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:_MAX_TYPES_IN_ATTR])
        attributes = {
            "package": pkg.name,
            "entry_count": str(sum(counts.values())),
            "type_count": str(len(counts)),
            "string_count": str(string_count),
            "types": top,
        }
        sidecar_rel = _write_sidecar(ws, pkg)
        if sidecar_rel is not None:
            attributes["sidecar"] = sidecar_rel
        findings.append(Finding(
            kind=const_resource_table_kind,
            subject=pkg.name or f"package 0x{pkg.id:x}",
            confidence=Confidence.LOW,
            state=FindingState.PRESENT,
            attributes=attributes,
            evidence=[Evidence(
                description=(f"{sum(counts.values())} resource entries across "
                             f"{len(counts)} types ({string_count} string values)"),
                snippet=const_arsc_name, tool="resources")],
            locations=[Location(file_path=const_arsc_name)],
        ))
    return findings
