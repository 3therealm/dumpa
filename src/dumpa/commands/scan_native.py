"""`dumpa scan-native` — native-library analysis as a first-class command.

Bare, it runs the zero-dep ELF scan (`scanners/native.py`) over a workspace's
`lib/<abi>/*.so` and prints a per-library summary. `--tool radare2` additionally runs the
opt-in radare2 region scan (`scanners/native_r2.py`): per-section entropy regions and a
function inventory over the primary ABI. radare2 is optional — when it (or r2pipe) is
absent the deep path warns and the command still prints the ELF-only results.

Accepts a populated workspace directory or an `.apk`/`.xapk` (extracted into a throwaway
workspace for the run). This is analysis-only; it does not persist a report (`analyze`
owns the report). Reuses the convert pipeline for extraction.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from dumpa.commands.analyze import input_type
from dumpa.convert.pipeline import build_workspace, prepare_convert
from dumpa.core.config import load_config
from dumpa.core.errors import DumpaError
from dumpa.core.hashing import sha256_file
from dumpa.core.report import Finding
from dumpa.core.tools import ToolRegistry, build_default_registry
from dumpa.core.workspace import Workspace, open_workspace
from dumpa.scanners import enrich_native_rvas, native, native_r2

logger = logging.getLogger("dumpa")

const_tool_radare2 = "radare2"


@contextmanager
def _open_target(registry: ToolRegistry, target: Path) -> Iterator[Workspace]:
    """Yield a populated workspace for a workspace dir or an .apk/.xapk input."""
    target_abs = target.resolve()
    if target_abs.is_dir():
        ws = Workspace(root=target_abs)
        if ws.read_meta() is None:
            raise DumpaError(f"{target_abs} is not a dumpa workspace; "
                             f"pass an .apk/.xapk or run analyze first")
        yield ws
        return

    in_type = input_type(target_abs)
    if in_type == "xapk":
        prepare_convert(registry, None)
    with open_workspace(None) as ws:
        build_workspace(registry, ws, target_abs, in_type, sha256_file(target_abs), None)
        yield ws


def _print(findings: list[Finding]) -> None:
    """Print one line per native finding: subject, kind, and a salient detail."""
    if not findings:
        print("no native libraries found")
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
        print(f"{subject.ljust(subj_w)}  {kind.ljust(kind_w)}  {detail}")


def scan_native(target: Path, *, tool: str | None = None) -> None:
    """Scan a workspace/apk's native libraries; `--tool radare2` adds region analysis."""
    if tool is not None and tool != const_tool_radare2:
        raise DumpaError(f"unsupported --tool {tool!r}: only 'radare2' is supported")

    config = load_config()
    registry = build_default_registry(config.tool_paths)
    with _open_target(registry, target) as ws:
        findings = native.scan(ws)
        if tool == const_tool_radare2:
            findings.extend(native_r2.scan(ws))
        findings = enrich_native_rvas(findings, ws)
        _print(findings)
