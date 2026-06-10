"""radare2 native region scanner (opt-in): entropy regions + function inventory.

The value-add the zero-dep ELF parser (`scanners/native.py`) cannot give: per-section
Shannon entropy (to flag packed/encrypted regions), a radare2 function inventory, and
disasm-level suspicious-region signals. Runs against the **primary ABI only** by default
(multi-ABI apks ship the same code per arch); opt into every ABI with `--all-abis`
(`DUMPA_NATIVE_R2_ALL_ABIS` / `[analysis] native_r2_all_abis`). Fail-soft: radare2 absent,
oversized libraries, or analysis timeouts produce a warning and no findings, never an error.

Opt-in: registered in `OPTIONAL_SPECS`, not the always-run pipeline (radare2 is optional
and analysis is slow). Reached via `dumpa scan-native --tool radare2` or `analyze --r2`.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from dumpa.core import r2
from dumpa.core.abi import select_primary_abi
from dumpa.core.config import load_config
from dumpa.core.errors import ToolNotFoundError
from dumpa.core.r2 import R2Analysis
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.tools import build_default_registry
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_native_region_kind = "native-region"
const_native_function_summary_kind = "native-function-summary"
const_radare2_tool = "radare2"

# Shannon entropy (0..8). Compressed/encrypted data sits near 8.0; normal code near 6.
_ENTROPY_PACKED = 7.2          # >= this: likely packed/encrypted (HIGH)
_ENTROPY_ELEVATED = 6.5        # >= this: elevated, flag for review (MEDIUM)
_OVERSIZED_FN_BYTES = 0x8000   # functions bigger than this hint at obfuscation/packing


def _function_count(analysis: R2Analysis) -> int:
    return analysis.total_function_count if analysis.total_function_count is not None else len(analysis.functions)


def _classify(entropy: float) -> tuple[str, Confidence] | None:
    """Map a section entropy to (classification, confidence), or None if not flagged."""
    if entropy >= _ENTROPY_PACKED:
        return ("packed", Confidence.HIGH)
    if entropy >= _ENTROPY_ELEVATED:
        return ("high-entropy", Confidence.MEDIUM)
    return None


def _write_sidecar(ws: Workspace, abi: str, so: Path, analysis: R2Analysis,
                   regions: list[dict[str, object]]) -> str | None:
    """Write the full radare2 analysis to dumps/native-r2/; return its rel path."""
    sidecar = ws.native_r2_dir / f"{abi}__{so.name}.json"
    payload = {
        "abi": abi, "lib": so.name, "r2_version": analysis.version,
        "sections": [{"name": s.name, "vaddr": s.vaddr, "offset": s.paddr,
                      "size": s.size, "perm": s.perm, "entropy": s.entropy}
                     for s in analysis.sections],
        "function_count": _function_count(analysis),
        "stored_function_count": len(analysis.functions),
        "functions_truncated": analysis.functions_truncated,
        "functions": [{"name": f.name, "vaddr": f.vaddr, "size": f.size, "nbbs": f.nbbs}
                      for f in analysis.functions],
        "regions": regions,
    }
    try:
        ws.native_r2_dir.mkdir(parents=True, exist_ok=True)
        with sidecar.open("w", encoding="UTF-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError:
        logger.warning("could not write native-r2 sidecar for %s", so, exc_info=True)
        return None
    return sidecar.relative_to(ws.root).as_posix()


def _region_findings(abi: str, rel: str, lib: str, analysis: R2Analysis,
                     ) -> tuple[list[Finding], list[dict[str, object]]]:
    """Build native-region findings for entropy + self-modifying sections."""
    findings: list[Finding] = []
    regions: list[dict[str, object]] = []
    version = analysis.version
    for s in analysis.sections:
        flags: list[tuple[str, Confidence]] = []
        if s.entropy is not None:
            hit = _classify(s.entropy)
            if hit is not None:
                flags.append(hit)
        # writable + executable section = potential self-modifying code.
        if "w" in s.perm and "x" in s.perm:
            flags.append(("self-modifying", Confidence.MEDIUM))
        for classification, confidence in flags:
            ent = f"{s.entropy:.2f}" if s.entropy is not None else "?"
            regions.append({"region": s.name, "classification": classification,
                            "entropy": s.entropy, "offset": s.paddr,
                            "vaddr": s.vaddr, "size": s.size})
            findings.append(Finding(
                kind=const_native_region_kind,
                subject=f"{abi}/{lib}:{s.name}",
                confidence=confidence,
                state=FindingState.PRESENT,
                attributes={"abi": abi, "lib": lib, "region": s.name,
                            "classification": classification,
                            "entropy": ent, "size": str(s.size)},
                evidence=[Evidence(
                    description=f"{classification}: entropy {ent} over {s.size} B",
                    snippet=s.name, tool="radare2", rule_version=version)],
                locations=[Location(file_path=rel, file_offset=s.paddr, rva=s.vaddr)],
            ))
    return findings, regions


def _summary_finding(abi: str, rel: str, lib: str, analysis: R2Analysis,
                     sidecar_rel: str | None) -> Finding:
    oversized = sum(1 for f in analysis.functions if f.size > _OVERSIZED_FN_BYTES)
    function_count = _function_count(analysis)
    attributes = {"abi": abi, "function_count": str(function_count),
                  "stored_function_count": str(len(analysis.functions)),
                  "oversized_count": str(oversized)}
    if analysis.functions_truncated:
        attributes["functions_truncated"] = "true"
    if sidecar_rel is not None:
        attributes["sidecar"] = sidecar_rel
    return Finding(
        kind=const_native_function_summary_kind,
        subject=f"{abi}/{lib}",
        confidence=Confidence.HIGH,
        state=FindingState.PRESENT,
        attributes=attributes,
        evidence=[Evidence(
            description=f"{function_count} functions, {oversized} oversized",
            snippet=rel, tool="radare2", rule_version=analysis.version)],
        locations=[Location(file_path=rel)],
    )


def scan(ws: Workspace) -> list[Finding]:
    """radare2 entropy/region + function inventory over the primary ABI (or every ABI
    when native_r2_all_abis is set)."""
    ex = ws.extracted_dir
    if not ex.is_dir():
        return []
    libs = sorted(ex.glob("lib/*/*.so"))
    if not libs:
        return []

    cfg = load_config()
    registry = build_default_registry(cfg.tool_paths)
    try:
        tool = registry.resolve(const_radare2_tool)
    except ToolNotFoundError:
        logger.warning("radare2 not found; skipping native region scan "
                       "(install radare2 to enable --tool radare2)")
        return []

    all_abis = cfg.analysis.native_r2_all_abis
    abis = sorted({so.parent.name for so in libs})
    primary = select_primary_abi(abis)
    if primary is None:
        return []

    findings: list[Finding] = []
    for so in libs:
        abi = so.parent.name
        if not all_abis and abi != primary:
            continue
        rel = so.relative_to(ex).as_posix()
        analysis = r2.analyze(so, argv_prefix=tool.argv_prefix, version=tool.version)
        if analysis is None:
            continue
        region_findings, regions = _region_findings(abi, rel, so.name, analysis)
        sidecar_rel = _write_sidecar(ws, abi, so, analysis, regions)
        findings.append(_summary_finding(abi, rel, so.name, analysis, sidecar_rel))
        findings.extend(region_findings)
    return findings
