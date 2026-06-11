"""Protobuf scanner: decode protobuf-like blobs and mine endpoints + secrets.

The endpoint scanner streams a URL regex over text-ish files but never globs a serialized
protobuf blob, so a URL or key carried in a length-delimited field goes unseen. This walks
the protobuf wire format (`core.protobuf`), pulls printable strings out of wire-type-2 fields
(including nested messages), and runs them through the existing endpoint URL harvester and the
`secrets` rule bundle — emitting the same `endpoint` / `secret` findings, located at the
field's byte offset.

Scope: explicit protobuf-ish files only (`**/*.pb`, `**/*.proto.bin`). Sniffing arbitrary
binary blobs for embedded protobuf is intentionally out (too noisy); widening the target set
is a future step. Findings are low confidence by nature — a decoded string may be dead config,
a template, or third-party.
"""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.core import protobuf as pbwire
from dumpa.core.fs import read_bytes_resilient
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.rules import load_builtin, match_content_strings
from dumpa.core.workspace import Workspace
from dumpa.scanners.endpoint import const_max_samples_per_host, harvest_urls

logger = logging.getLogger("dumpa")

const_protobuf_targets = ("**/*.pb", "**/*.proto.bin")
const_max_file_bytes = 64 << 20
const_min_str_len = 4
const_secrets_bundle = "secrets"


def _targets(extracted_dir: Path) -> list[Path]:
    root = extracted_dir.resolve()
    seen: set[Path] = set()
    files: list[Path] = []
    for glob in const_protobuf_targets:
        for path in sorted(extracted_dir.glob(glob)):
            if path.is_file() and path.resolve().is_relative_to(root) and path not in seen:
                seen.add(path)
                files.append(path)
    return files


def _endpoint_findings(walked: list[tuple[int, int, str]], rel: str) -> list[Finding]:
    """Harvest URLs from the decoded strings, one `endpoint` finding per host."""
    hosts: dict[str, tuple[int, list[str]]] = {}
    for _field, offset, text in walked:
        for host, url in harvest_urls(text.encode("utf-8", "replace")):
            off, samples = hosts.setdefault(host, (offset, []))
            if url not in samples and len(samples) < const_max_samples_per_host:
                samples.append(url)
    findings: list[Finding] = []
    for host, (offset, samples) in sorted(hosts.items()):
        findings.append(Finding(
            kind="endpoint", subject=host, confidence=Confidence.LOW,
            state=FindingState.PRESENT,
            evidence=[Evidence(description=f"URL {u}", snippet=u, tool="protobuf")
                      for u in samples],
            locations=[Location(file_path=rel, file_offset=offset, domain=host)],
        ))
    return findings


def scan(ws: Workspace) -> list[Finding]:
    """Decode .pb-like blobs in the extracted tree; mine endpoints + secrets from string fields."""
    if not ws.extracted_dir.is_dir():
        return []
    bundle = load_builtin(const_secrets_bundle)
    secret_rules = [r for r in bundle.rules if r.regex or r.strings]
    findings: list[Finding] = []
    for path in _targets(ws.extracted_dir):
        try:
            if path.stat().st_size > const_max_file_bytes:
                continue
            data = read_bytes_resilient(path)
        except OSError:
            logger.debug("protobuf scan: cannot read %s", path, exc_info=True)
            continue
        rel = path.relative_to(ws.extracted_dir).as_posix()
        walked = pbwire.walk_strings(data, min_len=const_min_str_len)
        if not walked:
            continue
        findings.extend(_endpoint_findings(walked, rel))
        strings = [(offset, text) for _field, offset, text in walked]
        findings.extend(match_content_strings(secret_rules, bundle, strings, rel))
    return findings
