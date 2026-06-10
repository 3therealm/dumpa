"""`dumpa scan-native` — native-library analysis as a first-class command.

Bare, it runs the zero-dep ELF scan (`scanners/native.py`) over a workspace's
`lib/<abi>/*.so` and prints a per-library summary. `--tool radare2` additionally runs the
opt-in radare2 region scan (`scanners/native_r2.py`): per-section entropy regions and a
function inventory over the primary ABI. radare2 is optional — when it is
absent the deep path warns and the command still prints the ELF-only results.

Accepts a populated workspace directory or an `.apk`/`.xapk` (extracted into a throwaway
workspace for the run). This is analysis-only; it does not persist a report (`analyze`
owns the report). Reuses the convert pipeline for extraction.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import typer

from dumpa.commands.base import open_target
from dumpa.core.config import const_env_native_r2_all_abis, load_config
from dumpa.core.errors import DumpaError
from dumpa.core.report import Finding
from dumpa.core.tools import build_default_registry
from dumpa.scanners import enrich_native_rvas, native, native_r2

logger = logging.getLogger("dumpa")

const_tool_radare2 = "radare2"


def _print(findings: list[Finding]) -> None:
    """Print one line per native finding: subject, kind, and a salient detail."""
    if not findings:
        typer.echo("no native libraries found")
        return
    rows: list[tuple[str, str, str]] = []
    for f in findings:
        if f.kind == "native":
            detail = f"{f.attributes.get('bitness', '?')} {f.attributes.get('machine', '?')}"
        elif f.kind == "native-symbol":
            detail = (f"{f.attributes.get('export_count', '?')} exports, "
                      f"{f.attributes.get('import_count', '?')} imports")
        elif f.kind == "native-function-summary":
            detail = (f"{f.attributes.get('function_count', '?')} functions, "
                      f"{f.attributes.get('oversized_count', '0')} oversized")
        elif f.kind == "native-region":
            detail = (f"{f.attributes.get('classification', '?')} "
                      f"(entropy {f.attributes.get('entropy', '?')})")
        else:
            detail = f.confidence.value
        rows.append((f.subject, f.kind, detail))
    subj_w = max(len(s) for s, _, _ in rows)
    kind_w = max(len(k) for _, k, _ in rows)
    for subject, kind, detail in rows:
        typer.echo(f"{subject.ljust(subj_w)}  {kind.ljust(kind_w)}  {detail}")


def scan_native(target: Path, *, tool: str | None = None, all_abis: bool = False) -> None:
    """Scan a workspace/apk's native libraries; `--tool radare2` adds region analysis."""
    if tool is not None and tool != const_tool_radare2:
        raise DumpaError(f"unsupported --tool {tool!r}: only 'radare2' is supported")
    if all_abis:
        os.environ[const_env_native_r2_all_abis] = "1"  # native_r2 reads this from config/env

    config = load_config()
    registry = build_default_registry(config.tool_paths)
    with open_target(registry, target) as ws:
        findings = native.scan(ws)
        if tool == const_tool_radare2:
            findings.extend(native_r2.scan(ws))
        findings = enrich_native_rvas(findings, ws)
        _print(findings)
