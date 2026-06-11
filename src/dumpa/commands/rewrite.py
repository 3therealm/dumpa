"""`dumpa rewrite` — bundle-driven find-and-replace over a workspace's smali tree.

Operates on the `smali/` tree (the `apktool d` output), never the original input, so
edits are reversible by re-decoding. `--pattern` previews; `--replace` + `--select`
applies; `--rebuild` repacks + re-signs into a patched apk (opt-in). Every applied edit
is recorded as a `rewrite` finding in the workspace report for auditability.

This is the toolkit's first code-*modification* surface: an explicitly opt-in feature for
inspecting/patching apps you own or are authorized to modify (see ROADMAP.md Phase 8).
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import replace as dataclass_replace
from pathlib import Path

from dumpa import __version__
from dumpa.commands.analyze import const_file_report_json
from dumpa.convert.build import pack_align_sign
from dumpa.core.config import load_config
from dumpa.core.errors import DumpaError
from dumpa.core.report import (
    AppFacts,
    Evidence,
    Finding,
    FindingState,
    Location,
    Report,
    read_json,
    write_json,
)
from dumpa.core.rewrite import (
    AppliedEdit,
    RewritePlan,
    apply_edits,
    parse_selection,
    plan_edits,
    rewrite_rules_from_bundle,
)
from dumpa.core.rules import load_bundle
from dumpa.core.tools import build_default_registry
from dumpa.core.workspace import Workspace
from dumpa.signing import resolve_signing
from dumpa.tools import apktool

logger = logging.getLogger("dumpa")


def rewrite(workspace: Path, *, pattern: Path, replace: Path | None = None,
            select: str | None = None, category: tuple[str, ...] = (),
            rebuild: bool = False, signing: str | None = None,
            out: Path | None = None) -> None:
    """Preview or apply rewrite rules over a workspace's smali tree.

    `--pattern` alone (or `--replace` without `--select`) is preview-only. Applying needs
    both a `--replace` bundle and an explicit `--select`.
    """
    ws = Workspace(root=workspace.resolve())
    if ws.read_meta() is None:
        raise DumpaError(f"{ws.root} is not a dumpa workspace; run `dumpa unpack` first")

    config = load_config()
    registry = build_default_registry(config.tool_paths)
    if not ws.has_smali():
        registry.require("apktool")
        logger.info("no smali tree; decoding apk -> smali")
        apktool.decode_apk(registry.resolve("apktool"), ws.app_apk, ws.smali_dir)

    active = replace if replace is not None else pattern
    bundle = load_bundle(active)
    rules = rewrite_rules_from_bundle(bundle)
    plan = plan_edits(ws.smali_dir, rules, categories=tuple(category))

    applying = replace is not None
    _render_preview(plan, applying=applying)

    if not applying or select is None:
        if applying and select is None:
            logger.info("preview only — pass --select to apply")
        return

    selection = parse_selection(select, len(plan.matches))
    edits = apply_edits(ws.smali_dir, plan, selection, rule_version=bundle.version)
    _record_findings(ws, edits)
    logger.info("applied %d edit(s) to %s", len(edits), ws.smali_dir)

    if rebuild:
        sign_config = resolve_signing(signing, config, registry)
        required = ("apktool", "zipalign", "apksigner") if sign_config else ("apktool", "zipalign")
        registry.require(*required)
        out_path = out.resolve() if out else Path.cwd() / f"{ws.root.name}-rewritten.apk"
        pack_align_sign(registry, ws.smali_dir, out_path, sign_config)
        logger.info("rebuilt apk: %s", out_path)


def _render_preview(plan: RewritePlan, *, applying: bool) -> None:
    for warning in plan.warnings:
        logger.warning("rewrite: %s", warning)
    if not plan.matches:
        logger.info("no matches")
        return
    for m in plan.matches:
        print(f"[{m.index}] {m.rule_subject} ({m.category}) {m.locator}")
        print(f"    - {m.before}")
        if m.after is not None:
            print(f"    + {m.after}")
    if applying:
        print(f"\n{len(plan.matches)} match(es) — select with --select all|2,5|1-3,7")
    else:
        print(f"\n{len(plan.matches)} match(es) (preview-only; --replace to substitute)")


def _edit_finding(edit: AppliedEdit) -> Finding:
    m = edit.match
    return Finding(
        kind="rewrite", subject=m.rule_subject, confidence=m.confidence,
        state=FindingState.PRESENT,
        attributes={"category": m.category, "action": "applied"},
        evidence=[Evidence(
            description=f"rewrote {m.locator}: {m.before!r} -> {m.after!r}",
            snippet=f"{m.before} -> {m.after}", tool="rewrite",
            rule_version=edit.rule_version)],
        locations=[Location(file_path=m.file_rel, file_offset=m.byte_offset)],
    )


def _record_findings(ws: Workspace, edits: list[AppliedEdit]) -> None:
    """Append rewrite findings to the workspace report (creating a minimal one if absent)."""
    if not edits:
        return
    findings = [_edit_finding(e) for e in edits]
    report_path = ws.reports_dir / const_file_report_json
    existing = read_json(report_path)
    if existing is not None:
        merged = list(existing.findings) + findings
        write_json(dataclass_replace(existing, findings=merged), report_path)
        return
    meta = ws.read_meta()
    assert meta is not None  # caller guarantees a workspace marker
    report = Report(
        dumpa_version=__version__,
        created=datetime.datetime.now(datetime.UTC).isoformat(),
        input_path=meta.input_path,
        facts=AppFacts(input_sha256=meta.input_sha256, input_size=meta.input_size),
        findings=findings,
    )
    write_json(report, report_path)
