"""Google Play store listing lookup — networked, opt-in, disk-cached.

Resolves a package name to its Play store *genre* (e.g. ``GAME_PUZZLE`` / "Puzzle"),
the one external signal the dump.cs pattern selector needs. Everything here fails
soft: offline, network disabled, a 404, or an unparseable page all return ``None`` so
a report still builds without a genre.

Reproducibility: a fetched listing is cached under ``cache/playstore/<package>.json``
with its fetch date; a stored listing replays identically offline and the date is
recorded in evidence, so a networked lookup never makes a report unauditable. The
cache honors a TTL (default 30 days) so a stale genre eventually refreshes.

Parsing the public listing HTML is inherently brittle (the page layout can change);
the parse is isolated in `_parse_listing` and fixture-tested. A future structured
source can drop in behind `fetch_listing` without touching callers.
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger("dumpa")

const_listing_url = "https://play.google.com/store/apps/details?id={package}&hl=en&gl=US"
const_default_ttl_days = 30
const_user_agent = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
const_max_listing_bytes = 4 << 20      # cap the page read; a listing is well under this

# A Play package looks like a reverse-DNS id; reject obvious junk before any fetch.
_PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
# Primary genre lives in a category link: /store/apps/category/GAME_PUZZLE
_GENRE_ID_RE = re.compile(r"/store/apps/category/(GAME_[A-Z_]+)")
_GENRE_LABEL_RE = re.compile(r'itemprop="genre"[^>]*>([^<]{1,60})<')


@dataclass(frozen=True)
class PlayListing:
    """The genre facts read from a Play store listing (or its cache)."""
    package: str
    genre: str                  # human label, e.g. "Puzzle" (falls back to genre_id)
    genre_id: str               # e.g. "GAME_PUZZLE"
    url: str
    fetched: str                # ISO-8601 UTC

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def is_valid_package(package: str) -> bool:
    return bool(_PKG_RE.match(package))


def _cache_path(cache_dir: Path, package: str) -> Path:
    return cache_dir / f"{package}.json"


def _read_cache(cache_dir: Path, package: str, ttl_days: int,
                now: datetime.datetime) -> PlayListing | None:
    """Return a cached listing when present and within TTL; else None (miss/expired)."""
    path = _cache_path(cache_dir, package)
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
        return PlayListing(
            package=str(data["package"]), genre=str(data["genre"]),
            genre_id=str(data["genre_id"]), url=str(data["url"]),
            fetched=str(data["fetched"]),
        )
    except KeyError:
        return None


def _write_cache(cache_dir: Path, listing: PlayListing) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = _cache_path(cache_dir, listing.package)
    try:
        path.write_text(json.dumps(listing.to_dict(), indent=2, sort_keys=True) + "\n",
                        encoding="UTF-8")
    except OSError:
        logger.debug("playstore: cannot write cache %s", path, exc_info=True)


def _parse_listing(html: str, package: str, url: str, fetched: str) -> PlayListing | None:
    """Extract (genre_id, genre label) from a Play listing page; None if not found."""
    m = _GENRE_ID_RE.search(html)
    if m is None:
        return None
    genre_id = m.group(1)
    label_m = _GENRE_LABEL_RE.search(html)
    genre = label_m.group(1).strip() if label_m else _genre_id_to_label(genre_id)
    return PlayListing(package=package, genre=genre, genre_id=genre_id,
                       url=url, fetched=fetched)


def _genre_id_to_label(genre_id: str) -> str:
    """Fallback label from a genre id: GAME_ROLE_PLAYING -> 'Role Playing'."""
    body = genre_id[len("GAME_"):] if genre_id.startswith("GAME_") else genre_id
    return body.replace("_", " ").title()


def _fetch_html(url: str, timeout: int) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": const_user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw: bytes = resp.read(const_max_listing_bytes)
    except (urllib.error.URLError, OSError, ValueError):
        logger.debug("playstore: fetch failed for %s", url, exc_info=True)
        return None
    return raw.decode("UTF-8", errors="replace")


def fetch_listing(package: str, *, cache_dir: Path, allow_network: bool,
                  timeout: int, ttl_days: int = const_default_ttl_days,
                  now: datetime.datetime | None = None) -> PlayListing | None:
    """Resolve a package's Play genre: cache first, then a network fetch if allowed.

    Returns None for an invalid package, a cache miss with network disabled, a failed
    fetch, or an unparseable page — callers treat None as "no genre".
    """
    if not is_valid_package(package):
        return None
    now = now or _now()
    cached = _read_cache(cache_dir, package, ttl_days, now)
    if cached is not None:
        return cached
    if not allow_network:
        return None
    url = const_listing_url.format(package=package)
    html = _fetch_html(url, timeout)
    if html is None:
        return None
    listing = _parse_listing(html, package, url, now.isoformat())
    if listing is None:
        return None
    _write_cache(cache_dir, listing)
    return listing
