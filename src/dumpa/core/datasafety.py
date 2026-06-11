"""Google Play Data Safety lookup — networked, opt-in, disk-cached.

Resolves a package name to the data-type categories the developer *declared* in the
Play store Data Safety form (the "Data collected" / "Data shared" sections). This is a
separate page from the listing parsed by `playstore.py`
(``/store/apps/datasafety?id=<pkg>``), so it has its own fetch + cache here. Everything
fails soft: offline, network disabled, a 404, or an unparseable page all return
``None`` so a report still builds without a disclosure.

Reproducibility mirrors `playstore.py`: a fetched disclosure is cached under
``cache/datasafety/<package>.json`` with its fetch date; a stored disclosure replays
identically offline and the date is recorded in evidence. The cache honors a TTL
(default 30 days) so a stale disclosure eventually refreshes.

Parsing the public page HTML is inherently brittle (the layout can change); the parse
is isolated in `_parse_datasafety` and fixture-tested. Each declared data-type category
is a semantic ``<h3>`` heading inside its section, which is more stable than the
minified CSS class names around it.
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

const_datasafety_url = "https://play.google.com/store/apps/datasafety?id={package}&hl=en&gl=US"
const_default_ttl_days = 30
const_user_agent = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
const_max_page_bytes = 4 << 20      # the page is large but well under this

# A Play package looks like a reverse-DNS id; reject obvious junk before any fetch.
_PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
# Each declared data-type category is an <h3> inside the "Data shared"/"Data collected"
# section; the section headers are <h2>. Both are matched tag-only (class names are
# minified and unstable).
_H3_RE = re.compile(r"<h3[^>]*>([^<]+)</h3>")


@dataclass(frozen=True)
class DataSafetyDisclosure:
    """The declared data-type categories read from a Play Data Safety page (or cache)."""
    package: str
    url: str
    fetched: str                        # ISO-8601 UTC
    collected: tuple[str, ...]          # "Data collected" data-type labels, sorted-distinct
    shared: tuple[str, ...]             # "Data shared" data-type labels, sorted-distinct

    def labels(self) -> set[str]:
        """All declared data-type labels (collected plus shared)."""
        return set(self.collected) | set(self.shared)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "collected": list(self.collected), "shared": list(self.shared)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DataSafetyDisclosure:
        return cls(
            package=str(data["package"]), url=str(data["url"]),
            fetched=str(data["fetched"]),
            collected=tuple(str(c) for c in data.get("collected", [])),
            shared=tuple(str(s) for s in data.get("shared", [])),
        )


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def is_valid_package(package: str) -> bool:
    return bool(_PKG_RE.match(package))


def _cache_path(cache_dir: Path, package: str) -> Path:
    return cache_dir / f"{package}.json"


def _read_cache(cache_dir: Path, package: str, ttl_days: int,
                now: datetime.datetime) -> DataSafetyDisclosure | None:
    """Return a cached disclosure when present and within TTL; else None (miss/expired)."""
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
        return DataSafetyDisclosure.from_dict(data)
    except KeyError:
        return None


def _write_cache(cache_dir: Path, disclosure: DataSafetyDisclosure) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = _cache_path(cache_dir, disclosure.package)
    try:
        path.write_text(json.dumps(disclosure.to_dict(), indent=2, sort_keys=True) + "\n",
                        encoding="UTF-8")
    except OSError:
        logger.debug("datasafety: cannot write cache %s", path, exc_info=True)


def _section(html: str, start_label: str, end_labels: tuple[str, ...]) -> str:
    """Slice the HTML from `start_label` to the first of `end_labels` after it (or end)."""
    i = html.find(start_label)
    if i < 0:
        return ""
    ends = [e for e in (html.find(label, i + 1) for label in end_labels) if e > 0]
    return html[i:min(ends)] if ends else html[i:]


def _parse_datasafety(html: str, package: str, url: str,
                      fetched: str) -> DataSafetyDisclosure | None:
    """Extract (collected, shared) data-type labels from a Data Safety page; None if absent.

    The page lays out two sections — "Data shared" then "Data collected" then "Security
    practices" — each listing its data-type categories as <h3> headings. We bound each
    section by those text anchors and read the <h3> labels within. None when neither
    section is present (an unlisted app or a layout change).
    """
    shared_html = _section(html, "Data shared", ("Data collected", "Security practices"))
    collected_html = _section(html, "Data collected", ("Security practices",))
    if not shared_html and not collected_html:
        return None
    shared = tuple(sorted({m.strip() for m in _H3_RE.findall(shared_html)}))
    collected = tuple(sorted({m.strip() for m in _H3_RE.findall(collected_html)}))
    if not shared and not collected:
        return None
    return DataSafetyDisclosure(package=package, url=url, fetched=fetched,
                                collected=collected, shared=shared)


def _fetch_html(url: str, timeout: int) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": const_user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw: bytes = resp.read(const_max_page_bytes)
    except (urllib.error.URLError, OSError, ValueError):
        logger.debug("datasafety: fetch failed for %s", url, exc_info=True)
        return None
    return raw.decode("UTF-8", errors="replace")


def fetch_datasafety(package: str, *, cache_dir: Path, allow_network: bool,
                     timeout: int, ttl_days: int = const_default_ttl_days,
                     now: datetime.datetime | None = None) -> DataSafetyDisclosure | None:
    """Resolve a package's Data Safety disclosure: cache first, then a network fetch.

    Returns None for an invalid package, a cache miss with network disabled, a failed
    fetch, or an unparseable/absent disclosure — callers treat None as "no disclosure".
    """
    if not is_valid_package(package):
        return None
    now = now or _now()
    cached = _read_cache(cache_dir, package, ttl_days, now)
    if cached is not None:
        return cached
    if not allow_network:
        return None
    url = const_datasafety_url.format(package=package)
    html = _fetch_html(url, timeout)
    if html is None:
        return None
    disclosure = _parse_datasafety(html, package, url, now.isoformat())
    if disclosure is None:
        return None
    _write_cache(cache_dir, disclosure)
    return disclosure
