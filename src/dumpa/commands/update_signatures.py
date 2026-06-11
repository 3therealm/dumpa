"""`dumpa update-signatures` — refresh imported signatures from upstream databases.

The only networked path in the toolkit's static core: `analyze` always reads the vendored
snapshot, never the network. This command fetches a signature database, transforms it (see
`core.exodus` / `core.trackercontrol` / `core.apkid`), and writes the result to the user
override bundle (`$XDG_CONFIG_HOME/dumpa/rules/<bundle>.toml`), which
`load_builtin` prefers over the in-repo vendored copy. Updates are explicit and versioned —
never silent — to preserve reproducibility. Point `--out` at the in-repo bundle to regenerate
the vendored snapshot.

`--db` selects the source:

- `exodus` (default) — class + network tracker signatures (JSON API) -> `trackers_exodus`.
- `trackercontrol` — host blocklist with company attribution (JSON) -> `trackers_trackercontrol`.
- `apkid` — packer/protector/obfuscator YARA signatures (multi-file) -> `protections_apkid`.

Engine rule bundles have no upstream feed and stay curated — there is no `--db engines`.
(AppBrain was evaluated as a tracker source but exposes no package/class signatures, only
display names, so it cannot drive a code-signature bundle.)
"""

from __future__ import annotations

import datetime
import json
import logging
import tomllib
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dumpa.core import apkid as apkid_mod
from dumpa.core.apkid import apkid_rules_to_bundle_toml, const_apkid_tree_url
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
const_max_apkid_files = 2000        # backstop on the rule-file enumeration


def _http_bytes(url: str) -> bytes:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": const_user_agent})
        with urllib.request.urlopen(req, timeout=const_fetch_timeout) as resp:
            raw: bytes = resp.read(const_max_fetch_bytes + 1)
    except (OSError, ValueError) as e:
        raise DumpaError(f"failed to fetch signatures from {url}: {e}") from e
    if len(raw) > const_max_fetch_bytes:
        raise DumpaError(
            f"failed to fetch signatures from {url}: response exceeds "
            f"{const_max_fetch_bytes} bytes")
    return raw


def _fetch_json(url: str) -> Any:
    raw = _http_bytes(url)
    try:
        return json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise DumpaError(f"failed to parse signatures from {url}: {e}") from e


def _fetch_text(url: str) -> str:
    return _http_bytes(url).decode("utf-8", errors="replace")


def _fetch_apkid_rules(url: str) -> str:
    """APKiD ships many `.yara` files; enumerate them via the git-tree API and concatenate.

    Each file's text is prefixed with a `// dumpa-apkid-source: <path>` marker so the pure
    transform can derive a category from the source path. A non-`api.github.com` `--source`
    (e.g. a `file://` fixture) is read as a single pre-concatenated document.
    """
    if "api.github.com" not in url:
        return _fetch_text(url)
    tree = _fetch_json(url)
    nodes = tree.get("tree", []) if isinstance(tree, dict) else []
    out: list[str] = []
    total = 0
    for node in nodes:
        if not isinstance(node, dict) or node.get("type") != "blob":
            continue
        path = node.get("path", "")
        if not (isinstance(path, str)
                and path.startswith(apkid_mod.const_apkid_rules_prefix)
                and path.endswith(".yara")):
            continue
        raw = _http_bytes(apkid_mod.const_apkid_raw_base + path)
        total += len(raw)
        if total > const_max_fetch_bytes:
            raise DumpaError("failed to fetch APKiD rules: combined size exceeds limit")
        out.append(f"{apkid_mod.const_source_marker} {path}\n"
                   + raw.decode("utf-8", errors="replace"))
        if len(out) >= const_max_apkid_files:
            break
    if not out:
        raise DumpaError(f"no APKiD .yara rule files found under {url}")
    return "\n".join(out)


@dataclass(frozen=True)
class _Source:
    """A signature DB: its default URL, networked fetch, transform, and target bundle name."""
    default_url: str
    transform: Callable[..., str]
    bundle: str
    fetch: Callable[[str], Any] = field(default=_fetch_json)


const_sources: dict[str, _Source] = {
    "exodus": _Source(const_exodus_url, exodus_records_to_bundle_toml, "trackers_exodus"),
    "trackercontrol": _Source(
        const_blacklist_url, trackercontrol_records_to_bundle_toml, "trackers_trackercontrol"),
    "apkid": _Source(
        const_apkid_tree_url, apkid_rules_to_bundle_toml, "protections_apkid",
        fetch=_fetch_apkid_rules),
}


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
    """Fetch a signature DB, transform it, and write the imported bundle."""
    spec = const_sources.get(db)
    if spec is None:
        choices = ", ".join(sorted(const_sources))
        raise DumpaError(f"unknown signature DB {db!r} (choices: {choices})")

    url = source or spec.default_url
    print(f"fetching {db} signatures from {url} ...")
    data = spec.fetch(url)
    fetched = datetime.datetime.now(datetime.UTC).date().isoformat()
    toml_text = spec.transform(data, fetched=fetched)

    before = _current_subjects(spec.bundle)
    after = _subjects(toml_text)

    target = out.resolve() if out is not None else _user_rules_path(spec.bundle)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(toml_text, encoding="utf-8")

    added = len(after - before)
    removed = len(before - after)
    print(f"wrote {len(after)} rule subject(s) to {target}")
    print(f"  +{added} added  -{removed} removed  ({len(after & before)} unchanged)")
