"""Unity Addressables scanner: attribute remote content-delivery endpoints.

The Addressable Asset System stores its content catalog under `assets/aa/`. Remote
groups embed http(s) load URLs in the catalog's internal-id list. This scanner streams
those catalog files (bounded, never whole-file) and emits an `engine-detail` finding per
remote host.

Value vs. the endpoint scanner: the Phase 6 endpoint scanner already harvests URLs from
JSON assets, so the raw URL is discovered there. This scanner's job is *semantic
attribution* — labelling those hosts as Addressables remote content — not raw discovery.
The emitted hosts flow through `enrich_domain_attribution` like any other.

Runs only behind the Unity gate (UNITY_SPECS) and self-gates on a catalog being present,
so it is a no-op everywhere else. A bounded URL regex (rather than a JSON parse) keeps it
robust to Addressables catalog schema drift across Unity versions.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_catalog_globs = (
    "assets/aa/**/catalog*.json",
    "assets/aa/catalog*.json",
    "assets/aa/**/catalog*.bundle",
)
const_chunk_size = 1 << 20
const_overlap = 2048
const_max_file_bytes = 512 << 20
const_max_hosts = 100
const_max_samples_per_host = 5

_URL_RE = re.compile(rb"(?:https?|wss?)://[A-Za-z0-9._~:/?#@!$&'()*+,;=%\[\]-]+")
_TRIM = ".,;:'\")]}>"


def _str_list() -> list[str]:
    return []


@dataclass
class _HostHits:
    samples: list[str] = field(default_factory=_str_list)
    file: str = ""
    offset: int = 0


def _host_of(url: str) -> str | None:
    rest = url.split("://", 1)[1] if "://" in url else ""
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    host = host.split("@")[-1].split(":")[0]
    return host.lower() or None


def _catalogs(extracted_dir: Path) -> list[Path]:
    root = extracted_dir.resolve()
    seen: set[Path] = set()
    files: list[Path] = []
    for glob in const_catalog_globs:
        for path in sorted(extracted_dir.glob(glob)):
            if path.is_file() and path.resolve().is_relative_to(root) and path not in seen:
                seen.add(path)
                files.append(path)
    return files


def _record(hosts: dict[str, _HostHits], raw: bytes, offset: int, rel: str) -> None:
    url = raw.decode("latin-1").rstrip(_TRIM)
    host = _host_of(url)
    if host is None:
        return
    hit = hosts.get(host)
    if hit is None:
        if len(hosts) >= const_max_hosts:
            return
        hit = _HostHits(file=rel, offset=offset)
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
                    continue  # possibly truncated at the chunk edge; re-caught next window
                _record(hosts, m.group(), window_start + m.start(), rel)
            base += len(chunk)
            tail = window[-const_overlap:]
        if tail:
            window_start = base - len(tail)
            for m in _URL_RE.finditer(tail):
                _record(hosts, m.group(), window_start + m.start(), rel)


def scan(ws: Workspace) -> list[Finding]:
    """Attribute Addressables remote content endpoints (no-op without a catalog)."""
    if not ws.extracted_dir.is_dir():
        return []
    catalogs = _catalogs(ws.extracted_dir)
    if not catalogs:
        return []  # not using Addressables remote content

    hosts: dict[str, _HostHits] = {}
    for path in catalogs:
        if len(hosts) >= const_max_hosts:
            break
        try:
            if path.stat().st_size > const_max_file_bytes:
                continue
            _scan_file(path, path.relative_to(ws.extracted_dir).as_posix(), hosts)
        except OSError:
            logger.debug("addressables scan: cannot read %s", path, exc_info=True)

    findings: list[Finding] = []
    for host, hit in sorted(hosts.items()):
        evidence = [Evidence(description=f"Addressables remote URL {url}", snippet=url, tool="unity")
                    for url in hit.samples]
        findings.append(Finding(
            kind="engine-detail", subject=f"Addressables remote content: {host}",
            confidence=Confidence.MEDIUM, state=FindingState.REFERENCED, attributes={},
            evidence=evidence,
            locations=[Location(file_path=hit.file, file_offset=hit.offset, domain=host)],
        ))
    return findings
