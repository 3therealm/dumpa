"""ASN / country lookup for observed hosts — networked, opt-in, disk-cached.

Resolves a host to its autonomous system (ASN + org) and country, the ownership-context
signal the domain attribution pass cannot get offline. Everything fails soft, mirroring
`playstore.py` / `datasafety.py`: offline, network disabled, an error, or an unparseable
response all return ``None`` so a report still builds without geo data.

Reproducibility: a fetched record is cached under ``cache/asn/<host>.json`` with its fetch
date; a stored record replays identically offline and the date is recorded in evidence.
The cache honors a TTL (default 90 days) so a stale record eventually refreshes.

The lookup uses ip-api.com's free JSON endpoint, which accepts a hostname directly (it
resolves DNS server-side) and needs no API key. The free tier is HTTP-only and rate
limited; this is an opt-in enrichment, never on the report's critical path. A future
offline source (a local MaxMind GeoLite2 DB) can drop in behind `fetch_asn_geo` without
touching callers.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from dumpa.core.report import Finding
    from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_lookup_url = "http://ip-api.com/json/{host}?fields=status,country,countryCode,as,org,query"
const_default_ttl_days = 90
const_user_agent = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
const_max_response_bytes = 64 << 10        # the JSON record is tiny
const_max_lookups = 50                     # bound the per-report network fan-out
const_asn_tool = "asn-geo"

# A bare host (reverse-DNS-ish): reject URLs, paths, and obvious junk before any fetch.
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class AsnGeoInfo:
    """ASN + country facts for one host (or its cache)."""
    host: str
    asn: str                    # e.g. "AS15169 Google LLC" (ip-api's `as` field)
    org: str                    # network operator name
    country: str                # ISO-3166 alpha-2 code, e.g. "US"
    fetched: str                # ISO-8601 UTC

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AsnGeoInfo:
        return cls(
            host=str(data["host"]), asn=str(data.get("asn", "")),
            org=str(data.get("org", "")), country=str(data.get("country", "")),
            fetched=str(data["fetched"]),
        )


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def is_valid_host(host: str) -> bool:
    return bool(_HOST_RE.match(host))


def _cache_path(cache_dir: Path, host: str) -> Path:
    return cache_dir / f"{host}.json"


def _read_cache(cache_dir: Path, host: str, ttl_days: int,
                now: datetime.datetime) -> AsnGeoInfo | None:
    """Return a cached record when present and within TTL; else None (miss/expired)."""
    path = _cache_path(cache_dir, host)
    if not path.is_file():
        return None
    try:
        data = cast("dict[str, Any]", json.loads(path.read_text(encoding="UTF-8")))
        fetched = datetime.datetime.fromisoformat(str(data["fetched"]))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, KeyError, ValueError):
        return None
    if now - fetched > datetime.timedelta(days=ttl_days):
        return None
    try:
        return AsnGeoInfo.from_dict(data)
    except KeyError:
        return None


def _write_cache(cache_dir: Path, info: AsnGeoInfo) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = _cache_path(cache_dir, info.host)
    try:
        path.write_text(json.dumps(info.to_dict(), indent=2, sort_keys=True) + "\n",
                        encoding="UTF-8")
    except OSError:
        logger.debug("asn: cannot write cache %s", path, exc_info=True)


def _parse(raw: str, host: str, fetched: str) -> AsnGeoInfo | None:
    """Parse an ip-api JSON record; None on a failed status or unusable payload."""
    try:
        data = cast("dict[str, Any]", json.loads(raw))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("status") != "success":
        return None
    asn = str(data.get("as", "")).strip()
    org = str(data.get("org", "")).strip()
    country = str(data.get("countryCode", "")).strip()
    if not asn and not country:
        return None
    return AsnGeoInfo(host=host, asn=asn, org=org, country=country, fetched=fetched)


def _fetch(url: str, timeout: int) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": const_user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw: bytes = resp.read(const_max_response_bytes)
    except (urllib.error.URLError, OSError, ValueError):
        logger.debug("asn: fetch failed for %s", url, exc_info=True)
        return None
    return raw.decode("UTF-8", errors="replace")


def fetch_asn_geo(host: str, *, cache_dir: Path, allow_network: bool,
                  timeout: int, ttl_days: int = const_default_ttl_days,
                  now: datetime.datetime | None = None) -> AsnGeoInfo | None:
    """Resolve a host's ASN/country: cache first, then a network fetch if allowed.

    Returns None for an invalid host, a cache miss with network disabled, a failed fetch,
    or an unusable response — callers treat None as "no geo data".
    """
    if not is_valid_host(host):
        return None
    now = now or _now()
    cached = _read_cache(cache_dir, host, ttl_days, now)
    if cached is not None:
        return cached
    if not allow_network:
        return None
    url = const_lookup_url.format(host=urllib.parse.quote(host, safe=""))
    raw = _fetch(url, timeout)
    if raw is None:
        return None
    info = _parse(raw, host, now.isoformat())
    if info is None:
        return None
    _write_cache(cache_dir, info)
    return info


def enrich_asn_geo(findings: list[Finding], ws: Workspace, *, allow_network: bool,
                   timeout: int, ttl_days: int = const_default_ttl_days) -> list[Finding]:
    """Stamp ASN/country attributes + evidence onto endpoint (host) findings. Idempotent.

    Looks up each `endpoint` finding's host (capped at const_max_lookups), attaching `asn`/
    `asn_org`/`country` attributes and a linking Evidence. With `allow_network=False` every
    lookup is a cache read, so a report built offline is unchanged unless a host was cached
    by a prior networked run — keeping the default (flag off) report reproducible.
    """
    from dumpa.core.report import Evidence

    hosts = [f.subject for f in findings if f.kind == "endpoint"]
    if not hosts:
        return findings
    resolved: dict[str, AsnGeoInfo] = {}
    for host in hosts:
        if len(resolved) >= const_max_lookups:
            break
        if host in resolved:
            continue
        info = fetch_asn_geo(host, cache_dir=ws.asn_cache_dir, allow_network=allow_network,
                             timeout=timeout, ttl_days=ttl_days)
        if info is not None:
            resolved[host] = info
    if not resolved:
        return findings

    out: list[Finding] = []
    for f in findings:
        info = resolved.get(f.subject) if f.kind == "endpoint" else None
        if info is None:
            out.append(f)
            continue
        attrs = dict(f.attributes)
        if info.asn and "asn" not in attrs:
            attrs["asn"] = info.asn
        if info.org and "asn_org" not in attrs:
            attrs["asn_org"] = info.org
        if info.country and "country" not in attrs:
            attrs["country"] = info.country
        desc = f"host in {info.country or '?'} via {info.asn or info.org or '?'}; fetched {info.fetched}"
        ev = Evidence(description=desc, tool=const_asn_tool)
        evidence = f.evidence if any(
            e.description == ev.description and e.tool == ev.tool for e in f.evidence
        ) else [*f.evidence, ev]
        out.append(dataclasses.replace(f, attributes=attrs, evidence=evidence))
    return out
