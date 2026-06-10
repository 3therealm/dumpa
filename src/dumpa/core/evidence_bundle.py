"""Write a standalone, portable evidence bundle from a Report.

The unified `Finding`/`Evidence`/`Location` model already carries every audit
detail (snippet, file hash, offset, RVA, tool, rule version); this packages it
into a self-contained `evidence/` directory you can archive or hand off without
the whole workspace:

    <dest>/
      manifest.json   the full findings (evidence + locations) + a facts header
      index.md        a human-readable, one-line-per-finding listing
      snippets/       one <NNNN>__<kind>__<slug>.txt per finding that has a snippet
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from dumpa.core.report import Finding, Report

const_dir_snippets = "snippets"
const_file_manifest = "manifest.json"
const_file_index = "index.md"

_slug_re = re.compile(r"[^a-z0-9]+")


def _slug(text: str) -> str:
    """Lowercase, collapse non-alphanumeric runs to '-', trim; '' -> 'finding'."""
    out = _slug_re.sub("-", text.lower()).strip("-")
    return out or "finding"


def _snippets(finding: Finding) -> list[tuple[str, str]]:
    """(evidence description, snippet) pairs for the evidence entries that carry one."""
    return [(e.description, e.snippet) for e in finding.evidence if e.snippet]


def _first(finding: Finding, attr: str) -> str | None:
    """First non-None value of `attr` across the finding's evidence entries."""
    for e in finding.evidence:
        value = getattr(e, attr)
        if value is not None:
            return value
    return None


def _location_bits(finding: Finding) -> list[str]:
    """Short location descriptors (file/offset/RVA/...) for the index line."""
    bits: list[str] = []
    for loc in finding.locations:
        if loc.file_path:
            bits.append(loc.file_path)
        if loc.file_offset is not None:
            bits.append(f"offset={loc.file_offset}")
        if loc.rva is not None:
            bits.append(f"rva={loc.rva}")
        if loc.dex_class:
            bits.append(loc.dex_class + (f".{loc.dex_method}" if loc.dex_method else ""))
        if loc.dex_field:
            bits.append(f"field={loc.dex_field}")
        if loc.dex_bytecode_offset is not None:
            bits.append(f"bytecode=+0x{loc.dex_bytecode_offset:x}")
        if loc.domain:
            bits.append(loc.domain)
    return bits


def write_evidence_bundle(report: Report, dest: Path) -> None:
    """Write the evidence bundle for `report` into directory `dest`."""
    snippets_dir = dest / const_dir_snippets
    snippets_dir.mkdir(parents=True, exist_ok=True)

    width = max(4, len(str(len(report.findings))))
    manifest_findings: list[dict[str, object]] = []
    index_lines = [f"# Evidence — {report.facts.package or report.input_path}", ""]

    for i, finding in enumerate(report.findings, start=1):
        record = finding.to_dict()
        snips = _snippets(finding)
        snippet_file: str | None = None
        if snips:
            name = f"{i:0{width}d}__{finding.kind}__{_slug(finding.subject)}.txt"
            body = "\n\n".join(f"# {desc}\n{snip}" for desc, snip in snips)
            (snippets_dir / name).write_text(body + "\n", encoding="UTF-8")
            snippet_file = f"{const_dir_snippets}/{name}"
            record["snippet_file"] = snippet_file
        manifest_findings.append(record)

        meta = [finding.confidence.value, finding.state.value]
        tool = _first(finding, "tool")
        rule_version = _first(finding, "rule_version")
        if tool:
            meta.append(f"tool={tool}")
        if rule_version:
            meta.append(f"rule={rule_version}")
        meta.extend(_location_bits(finding))
        line = f"- **{finding.kind}** `{finding.subject}` — {', '.join(meta)}"
        if snippet_file:
            line += f" ([snippet]({snippet_file}))"
        index_lines.append(line)

    manifest = {
        "dumpa_version": report.dumpa_version,
        "created": report.created,
        "input_path": report.input_path,
        "input_sha256": report.facts.input_sha256,
        "findings": manifest_findings,
    }
    (dest / const_file_manifest).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="UTF-8")
    (dest / const_file_index).write_text("\n".join(index_lines) + "\n", encoding="UTF-8")
