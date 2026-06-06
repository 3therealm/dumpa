"""Endpoint scanner: extract URLs/hosts referenced in the app.

Streams a URL regex over dex, native libs, resources, manifest, and text-ish assets
(never loading a file whole), dedupes by host, and emits one `endpoint` finding per
host with sample URLs and the first file/offset. This also backfills the tracker
"domain" signal — a host here may belong to a detected SDK.

Findings are low confidence by nature: a URL string in a binary may be dead, a
template, or third-party. Bare IPs and host-less domains are intentionally not
harvested (too noisy without a parser); that is left to later, structured work.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_endpoint_targets = (
    "**/*.dex", "lib/**/*.so", "resources.arsc", "AndroidManifest.xml",
    "**/*.json", "**/*.xml", "**/*.txt", "**/*.js", "**/*.cfg", "**/*.ini",
)
const_chunk_size = 1 << 20
const_overlap = 2048                 # >= longest URL we expect to span a chunk edge
const_max_file_bytes = 512 << 20
const_max_hosts = 100
const_max_samples_per_host = 5

# scheme://...  (the char class is the set of URL-legal bytes; trailing junk trimmed later)
_URL_RE = re.compile(rb"(?:https?|wss?)://[A-Za-z0-9._~:/?#@!$&'()*+,;=%\[\]-]+")
_TRIM = ".,;:'\")]}>"


@dataclass
class _HostHits:
    samples: list[str] = field(default_factory=list)
    file: str = ""
    offset: int = 0


def _host_of(url: str) -> str | None:
    rest = url.split("://", 1)[1] if "://" in url else ""
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    host = host.split("@")[-1].split(":")[0]
    return host.lower() or None


def _targets(extracted_dir: Path) -> list[Path]:
    root = extracted_dir.resolve()
    seen: set[Path] = set()
    files: list[Path] = []
    for glob in const_endpoint_targets:
        for path in sorted(extracted_dir.glob(glob)):
            if path.is_file() and path.resolve().is_relative_to(root) and path not in seen:
                seen.add(path)
                files.append(path)
    return files


def _record(hosts: dict[str, _HostHits], raw: bytes, abs_offset: int, rel: str) -> None:
    url = raw.decode("latin-1").rstrip(_TRIM)
    host = _host_of(url)
    if host is None:
        return
    hit = hosts.get(host)
    if hit is None:
        if len(hosts) >= const_max_hosts:
            return
        hit = _HostHits(file=rel, offset=abs_offset)
        hosts[host] = hit
    if url not in hit.samples and len(hit.samples) < const_max_samples_per_host:
        hit.samples.append(url)


def _scan_file(path: Path, rel: str, hosts: dict[str, _HostHits]) -> None:
    with path.open("rb") as f:
        tail = b""
        base = 0
        while True:
            chunk = f.read(const_chunk_size)
            if not chunk:
                break
            window = tail + chunk
            window_start = base - len(tail)
            for m in _URL_RE.finditer(window):
                if m.end() == len(window):
                    continue  # may be truncated at the chunk edge; re-caught next window
                _record(hosts, m.group(), window_start + m.start(), rel)
            base += len(chunk)
            tail = window[-const_overlap:]
        if tail:
            window_start = base - len(tail)
            for m in _URL_RE.finditer(tail):
                _record(hosts, m.group(), window_start + m.start(), rel)


def scan(ws: Workspace) -> list[Finding]:
    """Extract referenced URLs/hosts from the extracted tree."""
    if not ws.extracted_dir.is_dir():
        return []
    hosts: dict[str, _HostHits] = {}
    for path in _targets(ws.extracted_dir):
        if len(hosts) >= const_max_hosts:
            break
        try:
            if path.stat().st_size > const_max_file_bytes:
                continue
            _scan_file(path, path.relative_to(ws.extracted_dir).as_posix(), hosts)
        except OSError:
            logger.debug("endpoint scan: cannot read %s", path, exc_info=True)

    findings: list[Finding] = []
    for host, hit in sorted(hosts.items()):
        evidence = [Evidence(description=f"URL {url}", snippet=url, tool="endpoint") for url in hit.samples]
        findings.append(Finding(
            kind="endpoint", subject=host, confidence=Confidence.LOW,
            state=FindingState.PRESENT, attributes={},
            evidence=evidence,
            locations=[Location(file_path=hit.file, file_offset=hit.offset, domain=host)],
        ))
    return findings
