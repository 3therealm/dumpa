"""`dumpa update-signatures` — refresh imported tracker signatures from upstream DBs.

The only networked path in the toolkit's static core: `analyze` always reads the vendored
snapshot, never the network. This command fetches a tracker signature database, transforms
it (see `core.exodus` / `core.trackercontrol`), and writes the result to the user override
bundle (`$XDG_CONFIG_HOME/dumpa/rules/<bundle>.toml`), which `load_builtin` prefers over the
in-repo vendored copy. Updates are explicit and versioned — never silent — to preserve
reproducibility. Point `--out` at the in-repo bundle to regenerate the vendored snapshot.

`--db` selects the source: `exodus` (default; class + network signatures) or
`trackercontrol` (host blocklist with company attribution).
"""

from __future__ import annotations

import datetime
import json
import logging
import tomllib
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from dumpa.core.errors import DumpaError
from dumpa.core.exodus import const_exodus_url, exodus_records_to_bundle_toml
from dumpa.core.rules import _user_rules_path, load_builtin
from dumpa.core.trackercontrol import (
    const_blacklist_url,
    trackercontrol_records_to_bundle_toml,
)

logger = logging.getLogger("dumpa")

const_fetch_timeout = 60
const_user_agent = "dumpa/update-signatures"
const_max_fetch_bytes = 16 << 20


@dataclass(frozen=True)
class _Source:
    """A signature DB: its default URL, transform, and target bundle name."""
    default_url: str
    transform: Callable[..., str]
    bundle: str


const_sources: dict[str, _Source] = {
    "exodus": _Source(const_exodus_url, exodus_records_to_bundle_toml, "trackers_exodus"),
    "trackercontrol": _Source(
        const_blacklist_url, trackercontrol_records_to_bundle_toml, "trackers_trackercontrol"),
}


def _fetch(url: str) -> Any:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": const_user_agent})
        with urllib.request.urlopen(req, timeout=const_fetch_timeout) as resp:
            raw = resp.read(const_max_fetch_bytes + 1)
    except (OSError, ValueError) as e:
        raise DumpaError(f"failed to fetch signatures from {url}: {e}") from e
    if len(raw) > const_max_fetch_bytes:
        raise DumpaError(
            f"failed to fetch signatures from {url}: response exceeds "
            f"{const_max_fetch_bytes} bytes"
        )
    try:
        return json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise DumpaError(f"failed to parse signatures from {url}: {e}") from e


def _subjects(toml_text: str) -> set[str]:
    data = tomllib.loads(toml_text)
    rules = data.get("rule", [])
    return {r["subject"] for r in rules if isinstance(r, dict) and isinstance(r.get("subject"), str)}


def _current_subjects(bundle: str) -> set[str]:
    try:
        return {r.subject for r in load_builtin(bundle).rules}
    except DumpaError:
        return set()


def update_signatures(*, db: str = "exodus", source: str | None = None,
                      out: Path | None = None) -> None:
    """Fetch a tracker signature DB, transform it, and write the imported bundle."""
    spec = const_sources.get(db)
    if spec is None:
        choices = ", ".join(sorted(const_sources))
        raise DumpaError(f"unknown signature DB {db!r} (choices: {choices})")

    url = source or spec.default_url
    print(f"fetching {db} signatures from {url} ...")
    data = _fetch(url)
    fetched = datetime.datetime.now(datetime.UTC).date().isoformat()
    toml_text = spec.transform(data, fetched=fetched)

    before = _current_subjects(spec.bundle)
    after = _subjects(toml_text)

    target = out.resolve() if out is not None else _user_rules_path(spec.bundle)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(toml_text, encoding="utf-8")

    added = len(after - before)
    removed = len(before - after)
    print(f"wrote {len(after)} tracker(s) to {target}")
    print(f"  +{added} added  -{removed} removed  ({len(after & before)} unchanged)")
