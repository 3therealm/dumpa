"""Build a unified Report from a workspace.

This is the one place that turns external-tool output (aapt badging, apksigner
verify), the registered scanners, and the workspace marker into the pure
`core.report` model. Scanners (engine detection from Phase 4 onward) contribute the
findings; the rest is the facts header.
"""

from __future__ import annotations

import datetime
import logging

from dumpa import __version__
from dumpa.core.config import (
    const_default_validation_timeout,
    const_env_validation_timeout,
    load_config,
)
from dumpa.core.env import env_positive_int
from dumpa.core.errors import ToolExecutionError, ToolNotFoundError
from dumpa.core.manifest import load_manifest
from dumpa.core.privacy import permission_findings
from dumpa.core.privacy_compare import compare, resolve_disclosure
from dumpa.core.report import AppFacts, Report
from dumpa.core.tools import ToolRegistry
from dumpa.core.workspace import Workspace
from dumpa.scanners import game_types, primary_engine, run_all
from dumpa.tools import aapt, apksigner

logger = logging.getLogger("dumpa")


def _validation_timeout() -> int:
    return env_positive_int(const_env_validation_timeout, const_default_validation_timeout)


def _prefer(primary: str | None, fallback: str | None) -> str | None:
    """The manifest value when present, else the aapt-badging fallback."""
    return primary if primary else fallback


def _read_badging(registry: ToolRegistry, ws: Workspace) -> aapt.BadgingInfo:
    try:
        tool = registry.resolve('aapt')
    except ToolNotFoundError:
        return aapt.BadgingInfo()
    return aapt.read_badging(tool, ws.app_apk, _validation_timeout())


def _read_signer(registry: ToolRegistry, ws: Workspace) -> apksigner.SignerInfo | None:
    try:
        tool = registry.resolve('apksigner')
    except ToolNotFoundError:
        return None
    try:
        out = apksigner.verify(tool, ws.app_apk, _validation_timeout(), quiet=True)
    except ToolExecutionError:
        return None  # unsigned -> verify exits non-zero
    return apksigner.parse_verify_output(out)


def build_report(registry: ToolRegistry, ws: Workspace, *, use_cache: bool = True) -> Report:
    """Assemble the unified Report for a populated workspace.

    Scanner findings are served from the per-scanner content-hash cache when available;
    pass use_cache=False to force a fresh scan (the `--no-cache` path).
    """
    meta = ws.read_meta()
    if meta is None:
        raise ValueError(f"workspace {ws.root} has no marker; run `dumpa analyze` first")

    badging = _read_badging(registry, ws)
    signer = _read_signer(registry, ws)
    schemes = list(signer.schemes) if signer else []
    manifest = load_manifest(ws)

    # Manifest is the source of truth; aapt badging is the fallback when AXML parsing
    # failed (and the only source for ABIs, which live in the native-code listing).
    permissions = list(manifest.permissions) if manifest else list(badging.permissions)

    findings = run_all(ws, use_cache=use_cache)
    findings.extend(permission_findings(permissions))

    # Data Safety comparison runs here (not as a scanner) because it reconciles the
    # observed categories — including the capability findings just appended above —
    # against the developer's Play disclosure. Opt-in via the same play_lookup flag.
    analysis = load_config().analysis
    disclosure = resolve_disclosure(ws, allow_network=analysis.play_lookup,
                                    timeout=analysis.play_timeout,
                                    ttl_days=analysis.play_cache_ttl_days)
    if disclosure is not None:
        findings.extend(compare(disclosure, findings))

    facts = AppFacts(
        input_sha256=meta.input_sha256,
        input_size=meta.input_size,
        package=_prefer(manifest.package if manifest else None, badging.package),
        version_name=_prefer(manifest.version_name if manifest else None, badging.version_name),
        version_code=_prefer(manifest.version_code if manifest else None, badging.version_code),
        min_sdk=_prefer(manifest.min_sdk if manifest else None, badging.min_sdk),
        target_sdk=_prefer(manifest.target_sdk if manifest else None, badging.target_sdk),
        engine=primary_engine(findings),
        game_types=game_types(findings),
        abis=list(badging.abis),
        permissions=permissions,
        signer_cert_sha256=signer.cert_sha256 if signer else None,
        signing_schemes=schemes,
        signer_is_debug=signer.is_debug if signer else None,
        debuggable=manifest.debuggable if manifest else None,
        allow_backup=manifest.allow_backup if manifest else None,
        exported_component_count=len(manifest.exported_components) if manifest else None,
    )

    warnings: list[str] = []
    if manifest is None:
        warnings.append("manifest parse failed; facts fell back to aapt badging")
    if not schemes:
        warnings.append("apk is unsigned")
    if analysis.play_lookup and disclosure is None:
        warnings.append("Data Safety lookup enabled but no disclosure resolved "
                        "(app not listed or fetch failed)")

    return Report(
        dumpa_version=__version__,
        created=datetime.datetime.now(datetime.UTC).isoformat(),
        input_path=meta.input_path,
        facts=facts,
        tool_versions=dict(meta.tool_versions),
        findings=findings,
        warnings=warnings,
    )
