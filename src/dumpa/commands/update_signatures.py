"""`dumpa update-signatures` — refresh imported tracker signatures from Exodus Privacy.

The only networked path in the toolkit's static core: `analyze` always reads the vendored
snapshot, never the network. This command fetches the Exodus tracker database, transforms
it (see `core.exodus`), and writes the result to the user override bundle
(`$XDG_CONFIG_HOME/dumpa/rules/trackers_exodus.toml`), which `load_builtin` prefers over
the in-repo vendored copy. Updates are explicit and versioned — never silent — to preserve
reproducibility. Point `--out` at the in-repo bundle to regenerate the vendored snapshot.
"""

from __future__ import annotations

import datetime
import json
import logging
import tomllib
import urllib.request
from pathlib import Path
from typing import Any

from dumpa.core.errors import DumpaError
from dumpa.core.exodus import const_exodus_url, exodus_records_to_bundle_toml
from dumpa.core.rules import _user_rules_path, load_builtin

logger = logging.getLogger("dumpa")

const_fetch_timeout = 60
const_user_agent = "dumpa/update-signatures"


def _fetch(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": const_user_agent})
    try:
        with urllib.request.urlopen(req, timeout=const_fetch_timeout) as resp:
            return json.loads(resp.read().decode())
    except (OSError, ValueError) as e:
        raise DumpaError(f"failed to fetch Exodus signatures from {url}: {e}") from e


def _subjects(toml_text: str) -> set[str]:
    data = tomllib.loads(toml_text)
    rules = data.get("rule", [])
    return {r["subject"] for r in rules if isinstance(r, dict) and isinstance(r.get("subject"), str)}


def _current_subjects() -> set[str]:
    try:
        return {r.subject for r in load_builtin("trackers_exodus").rules}
    except DumpaError:
        return set()


def update_signatures(*, source: str | None = None, out: Path | None = None) -> None:
    """Fetch the Exodus tracker DB, transform it, and write the imported bundle."""
    url = source or const_exodus_url
    print(f"fetching Exodus signatures from {url} ...")
    data = _fetch(url)
    fetched = datetime.datetime.now(datetime.UTC).date().isoformat()
    toml_text = exodus_records_to_bundle_toml(data, fetched=fetched)

    before = _current_subjects()
    after = _subjects(toml_text)

    target = out.resolve() if out is not None else _user_rules_path("trackers_exodus")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(toml_text, encoding="utf-8")

    added = len(after - before)
    removed = len(before - after)
    print(f"wrote {len(after)} tracker(s) to {target}")
    print(f"  +{added} added  -{removed} removed  ({len(after & before)} unchanged)")
