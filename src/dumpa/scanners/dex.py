"""DEX scanner: per-file class/method/field inventory for every classesN.dex.

Parses each DEX structurally (no external tool, no bytecode decode) and emits one compact
`dex` finding carrying class/method counts; the full class inventory (names, superclass,
methods, fields) is written to a sidecar under `dumps/dex/` so the report stays small.
Offset -> class/method resolution for findings located inside a dex is a separate
cross-cutting pass in `scanners.enrich_dex_locations`.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from dumpa.core.dex import DexFile, parse_dex
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_dex_kind = "dex"


def _write_sidecar(ws: Workspace, dex_path: Path, dex: DexFile) -> str | None:
    """Write the full class inventory to dumps/dex/; return its rel path or None."""
    sidecar = ws.dex_dir / f"{dex_path.name}.json"
    payload = {
        "dex": dex_path.name,
        "version": dex.version,
        "classes": [{"name": c.name, "superclass": c.superclass,
                     "methods": list(c.method_names), "fields": list(c.field_names)}
                    for c in dex.classes],
    }
    try:
        ws.dex_dir.mkdir(parents=True, exist_ok=True)
        with sidecar.open("w", encoding="UTF-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError:
        logger.warning("could not write dex sidecar for %s", dex_path, exc_info=True)
        return None
    return sidecar.relative_to(ws.root).as_posix()


def scan(ws: Workspace) -> list[Finding]:
    """Report a class/method inventory for each classesN.dex in the workspace."""
    ex = ws.extracted_dir
    if not ex.is_dir():
        return []
    findings: list[Finding] = []
    for dex_path in sorted(ex.glob("**/*.dex")):
        dex = parse_dex(dex_path)
        if dex is None:
            continue
        rel = dex_path.relative_to(ex).as_posix()
        method_count = sum(len(c.method_names) for c in dex.classes)
        field_count = sum(len(c.field_names) for c in dex.classes)
        attributes = {"class_count": str(len(dex.classes)),
                      "method_count": str(method_count),
                      "field_count": str(field_count)}
        sidecar_rel = _write_sidecar(ws, dex_path, dex)
        if sidecar_rel is not None:
            attributes["sidecar"] = sidecar_rel
        findings.append(Finding(
            kind=const_dex_kind,
            subject=dex_path.name,
            confidence=Confidence.HIGH,
            state=FindingState.PRESENT,
            attributes=attributes,
            evidence=[Evidence(
                description=(f"{len(dex.classes)} classes, {method_count} methods, "
                             f"{field_count} fields"),
                snippet=rel, tool="dex")],
            locations=[Location(file_path=rel)],
        ))
    return findings
