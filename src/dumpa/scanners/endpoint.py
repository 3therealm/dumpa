"""Endpoint scanner: extract URLs/hosts (and bare IPs) referenced in the app.

Streams a URL regex over dex, native libs, resources, manifest, and text-ish assets
(never loading a file whole), dedupes by host, and emits one `endpoint` finding per
host with sample URLs and the first file/offset. This also backfills the tracker
"domain" signal — a host here may belong to a detected SDK.

A second pass harvests IPv4 literals (an IP that is the host of a URL is already captured
by the URL pass) into distinct `ip-endpoint` findings, kept out of the domain/blocklist
exports. A raw dotted-quad in a binary is dominated by version strings (`3.0.1.1`) and
opcode bytes, so — beyond octet validation, host-ish-neighbour rejection (excludes
`1.2.3.4.5` runs and URL-embedded IPs), and dropping reserved/loopback/experimental
addresses — a candidate is only reported when its context marks it as a real network
address: it carries a `:port` suffix, or it is a multicast/special-use address (e.g. the
SSDP/mDNS group). A portless unicast literal is indistinguishable from a version string
without a parser, so it is intentionally not harvested. Private RFC1918 ranges are tagged,
not dropped. IPv6 is deferred (rarer, far noisier without a parser).

Findings are low confidence by nature: a URL string in a binary may be dead, a
template, or third-party. Host-less domains are intentionally not harvested.
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
const_max_ips = 100
const_max_samples_per_host = 5

# scheme://...  (the char class is the set of URL-legal bytes; trailing junk trimmed later)
_URL_RE = re.compile(rb"(?:https?|wss?)://[A-Za-z0-9._~:/?#@!$&'()*+,;=%\[\]-]+")
_TRIM = ".,;:'\")]}>"

# A dotted quad. Octet range and "bareness" (no host-ish neighbour) are enforced in code,
# not the regex: a byte adjacent to one of these means the IP is part of a longer number
# (`1.2.3.4.5`), a hostname, or a URL path/host already captured by the URL pass.
_IPV4_RE = re.compile(rb"(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
_HOSTISH = frozenset(b"0123456789abcdefABCDEFghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ.-/@")


def _str_list() -> list[str]:
    return []


@dataclass
class _HostHits:
    samples: list[str] = field(default_factory=_str_list)
    file: str = ""
    offset: int = 0


@dataclass
class _IpHit:
    file: str = ""
    offset: int = 0
    scope: str = "public"        # public | private | multicast


def _ip_scope(ip: str) -> str | None:
    """Classify a dotted quad: 'public' | 'private' | 'multicast', or None if not a real IP.

    None rejects: a bad octet (>255), the unspecified/broadcast addresses, loopback
    (127.0.0.0/8), and reserved/experimental space (240.0.0.0/4) — none a meaningful
    endpoint. Multicast (224.0.0.0/4) is its own scope (always a real network address).
    RFC1918 + link-local + CGNAT ranges classify as 'private' so they can be tagged.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    a, b = octets[0], octets[1]
    if a == 0 or a == 127 or a >= 240:
        return None
    if 224 <= a <= 239:
        return "multicast"
    if (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or (a == 169 and b == 254) or (a == 100 and 64 <= b <= 127)):
        return "private"
    return "public"


def _has_port(window: bytes, end: int) -> bool:
    """True when the IP at [..end] is followed by ':<1-5 digits>' (a port suffix).

    A port is the strongest cheap signal that a dotted-quad is a network address rather
    than a version string. Returns False at the window edge (re-caught via the overlap).
    """
    if end >= len(window) or window[end:end + 1] != b":":
        return False
    i = end + 1
    while i < len(window) and i - end <= 5 and 0x30 <= window[i] <= 0x39:
        i += 1
    return i > end + 1 and (i >= len(window) or not (0x30 <= window[i] <= 0x39))


def _record_ip(ips: dict[str, _IpHit], window: bytes, start: int, end: int,
               abs_offset: int, rel: str) -> None:
    """Record an IPv4 match, gating on neighbours, scope, and network-address context."""
    if start > 0 and window[start - 1] in _HOSTISH:
        return                                   # part of a hostname / longer number / URL
    if end < len(window) and window[end] in _HOSTISH:
        return                                   # trailing octet (1.2.3.4.5) or path/host
    scope = _ip_scope(window[start:end].decode("latin-1"))
    if scope is None:
        return
    # A portless unicast literal is indistinguishable from a version string; only a port
    # suffix or multicast/special-use scope marks it as a real network address.
    if scope != "multicast" and not _has_port(window, end):
        return
    ip = window[start:end].decode("latin-1")
    if ip in ips or len(ips) >= const_max_ips:
        return
    ips[ip] = _IpHit(file=rel, offset=abs_offset, scope=scope)


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


def _scan_window(window: bytes, window_start: int, rel: str, is_tail: bool,
                 hosts: dict[str, _HostHits], ips: dict[str, _IpHit]) -> None:
    for m in _URL_RE.finditer(window):
        if not is_tail and m.end() == len(window):
            continue  # may be truncated at the chunk edge; re-caught next window
        _record(hosts, m.group(), window_start + m.start(), rel)
    for m in _IPV4_RE.finditer(window):
        if not is_tail and m.end() == len(window):
            continue  # may be truncated at the chunk edge; re-caught next window
        _record_ip(ips, window, m.start(), m.end(), window_start + m.start(), rel)


def _scan_file(path: Path, rel: str, hosts: dict[str, _HostHits],
               ips: dict[str, _IpHit]) -> None:
    with path.open("rb") as f:
        tail = b""
        base = 0
        while True:
            chunk = f.read(const_chunk_size)
            if not chunk:
                break
            window = tail + chunk
            _scan_window(window, base - len(tail), rel, is_tail=False, hosts=hosts, ips=ips)
            base += len(chunk)
            tail = window[-const_overlap:]
        if tail:
            _scan_window(tail, base - len(tail), rel, is_tail=True, hosts=hosts, ips=ips)


def scan(ws: Workspace) -> list[Finding]:
    """Extract referenced URLs/hosts from the extracted tree."""
    if not ws.extracted_dir.is_dir():
        return []
    hosts: dict[str, _HostHits] = {}
    ips: dict[str, _IpHit] = {}
    for path in _targets(ws.extracted_dir):
        if len(hosts) >= const_max_hosts and len(ips) >= const_max_ips:
            break
        try:
            if path.stat().st_size > const_max_file_bytes:
                continue
            _scan_file(path, path.relative_to(ws.extracted_dir).as_posix(), hosts, ips)
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
    # Bare IPs are a separate kind with no Location.domain, so report_domains / blocklist
    # exports (which key on kind == "endpoint" and Location.domain) never pick them up.
    for ip, ihit in sorted(ips.items()):
        findings.append(Finding(
            kind="ip-endpoint", subject=ip, confidence=Confidence.LOW,
            state=FindingState.PRESENT, attributes={"scope": ihit.scope},
            evidence=[Evidence(description=f"{ihit.scope} IPv4 literal", snippet=ip,
                               tool="endpoint")],
            locations=[Location(file_path=ihit.file, file_offset=ihit.offset)],
        ))
    return findings
