"""`dumpa xref` — trace an entity across every analysis layer.

With no entity, builds (and caches) the cross-reference index and lists the entities that
span two or more layers. With an entity, prints every place it appears — including
single-layer entities the cached index omits. Accepts a workspace directory or an
apk/xapk (extracted into a throwaway workspace, mirroring `dumpa diff`).
"""

from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path

from dumpa.commands.analyze import open_for_diff
from dumpa.core.errors import DumpaError
from dumpa.core.report import Finding
from dumpa.core.workspace import Workspace
from dumpa.core.xref import (
    Xref,
    XrefEntity,
    build_xref,
    query_xref,
    read_xref,
    render_xref_entity,
    render_xref_list,
    to_json,
    write_xref,
)

logger = logging.getLogger("dumpa")


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def _load_or_build(ws: Workspace, findings: list[Finding], *, use_cache: bool) -> Xref:
    """Reuse dumps/xref.json when it matches the workspace input; otherwise rebuild."""
    meta = ws.read_meta()
    input_sha = meta.input_sha256 if meta is not None else ""
    if use_cache:
        cached = read_xref(ws.xref_sidecar)
        if cached is not None and cached.provenance.input_sha256 == input_sha:
            return cached
    xref_index = build_xref(ws, findings, input_sha256=input_sha, built=_now())
    write_xref(xref_index, ws.xref_sidecar)
    return xref_index


def _entity_json(entity: XrefEntity) -> str:
    return json.dumps(entity.to_dict(), indent=2, sort_keys=True) + "\n"


def xref(workspace: Path, *, entity: str | None = None, min_layers: int = 2,
         case_insensitive: bool = False, json_: bool = False,
         out: Path | None = None, use_cache: bool = True) -> None:
    """Build the cross-reference index for a workspace, or query one entity within it."""
    with open_for_diff(workspace) as (ws, report):
        findings = list(report.findings)
        if entity is None:
            index = _load_or_build(ws, findings, use_cache=use_cache)
            text = to_json(index) if json_ else render_xref_list(index, min_layers=min_layers)
        else:
            found = query_xref(ws, findings, entity, case_insensitive=case_insensitive)
            if found is None:
                raise DumpaError(f"entity not found in any layer: {entity!r}")
            text = _entity_json(found) if json_ else render_xref_entity(found)

    if out is not None:
        out.write_text(text, encoding="UTF-8")
        logger.info("wrote xref output: %s", out)
    else:
        print(text, end="" if text.endswith("\n") else "\n")
