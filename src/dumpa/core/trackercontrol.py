"""Import the TrackerControl tracker database into a dumpa rule bundle.

TrackerControl (https://trackercontrol.org) ships a host blocklist with company
attribution at ``app/src/main/assets/xray-blacklist.json``. It is a *host/DNS* list — it
maps tracker hostnames to the owning product and parent company — built from the Disconnect
list, the DuckDuckGo Tracker Radar, and TrackerControl's own analysis of ~2M apps. Unlike
Exodus it carries **no class signatures and no purpose categories**.

Schema (a list of records; this transform is tolerant of the documented object, a bare map,
or a list — see ``_records``)::

    {"doms": ["criteo.com", "criteo.net"], "owner_name": "Criteo",
     "parent": null, "root_parent": null, "country": "fr"}
    {"doms": ["tynt.com"], "owner_name": "tynt",
     "parent": "33Across", "root_parent": "33Across", "country": "us"}

Mapping (mirrors ``core.exodus`` — a pure transform: parsed records -> a TOML rule bundle
string, no network and no disk I/O):

- each ``doms`` host -> an escaped-literal ``regex`` in one ``tracker`` rule (the same
  host-as-network-signature handling as Exodus' ``network_signature``; the content matcher
  scans dex/native/resource bytes for the host string).
- ``owner_name`` -> ``subject``; ``root_parent``/``parent`` (the company) -> ``owner``,
  falling back to ``owner_name`` when self-owned (parent fields null).
- **no category** is emitted: the source carries none and fabricating one would be wrong;
  the report buckets category-less trackers under "uncategorized".
- records flagged ``necessary`` (functionally required hosts, not trackers) are skipped.
- all rules are ``confidence = "medium"`` — the curated ``trackers.toml`` stays
  authoritative (curated wins on overlap at scan time).

Reuses Exodus' ``_toml_basic`` (TOML string escaping) and ``_valid_signature`` (compile +
min-length guard) — general-purpose, not Exodus-specific.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from dumpa.core.exodus import _toml_basic, _valid_signature

const_blacklist_url = (
    "https://raw.githubusercontent.com/TrackerControl/tracker-control-android/"
    "master/app/src/main/assets/xray-blacklist.json"
)
const_bundle_name = "trackers-trackercontrol"
const_source = f"TrackerControl xray-blacklist ({const_blacklist_url})"
const_license = (
    "TrackerControl tracker data — see https://trackercontrol.org "
    "(tracker-control-android, GPL-3.0 project)"
)
const_confidence = "medium"


def _records(data: Any) -> list[dict[str, Any]]:
    """Normalize the xray-blacklist payload to a list of tracker dicts.

    Accepts a bare list (the shipped form), a ``{"trackers": [...]}`` wrapper, or a
    ``{"<id>": {...}}`` map.
    """
    if isinstance(data, list):
        return [v for v in data if isinstance(v, dict)]
    if isinstance(data, dict):
        inner = data.get("trackers", data)
        if isinstance(inner, list):
            return [v for v in inner if isinstance(v, dict)]
        if isinstance(inner, dict):
            return [v for v in inner.values() if isinstance(v, dict)]
    return []


def _owner(rec: dict[str, Any]) -> str:
    """The owning company: root_parent, else parent, else the product name itself."""
    for key in ("root_parent", "parent", "owner_name"):
        val = rec.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _host_regexes(doms: Any) -> list[str]:
    """Escaped-literal regex sources for each usable host (de-duplicated, order-stable)."""
    out: list[str] = []
    seen: set[str] = set()
    if not isinstance(doms, list):
        return out
    for dom in doms:
        if not isinstance(dom, str) or not dom.strip():
            continue
        sig = _valid_signature(re.escape(dom.strip()))
        if sig is not None and sig not in seen:
            seen.add(sig)
            out.append(sig)
    return out


def _rule_block(subject: str, *, regexes: list[str], owner: str) -> str:
    lines = [
        "[[rule]]",
        'kind = "tracker"',
        f"subject = {_toml_basic(subject)}",
        f'confidence = "{const_confidence}"',
    ]
    if owner:
        lines.append(f"owner = {_toml_basic(owner)}")
    sources = ", ".join(_toml_basic(r) for r in regexes)
    lines.append(f"regex = [{sources}]")
    return "\n".join(lines)


def trackercontrol_records_to_bundle_toml(data: Any, *, fetched: str) -> str:
    """Transform parsed xray-blacklist records into a dumpa rule-bundle TOML string.

    ``fetched`` is the import date (YYYY-MM-DD), recorded as ``[bundle].updated``. The
    bundle ``version`` is ``trackercontrol.<count>.<hash8>`` over the emitted rule content,
    so re-importing identical upstream data yields an identical version — and therefore does
    not spuriously bust the per-scanner content cache.
    """
    blocks: list[str] = []
    subjects = 0
    for rec in _records(data):
        if rec.get("necessary") is True:
            continue
        name = rec.get("owner_name")
        if not isinstance(name, str) or not name.strip():
            continue
        regexes = _host_regexes(rec.get("doms"))
        if not regexes:
            continue
        subjects += 1
        blocks.append(_rule_block(name.strip(), regexes=regexes, owner=_owner(rec)))

    body = "\n\n".join(blocks)
    digest = hashlib.sha256(body.encode()).hexdigest()[:8]
    version = f"trackercontrol.{subjects}.{digest}"
    header = "\n".join([
        "# Imported TrackerControl tracker signatures (generated — do not edit by hand).",
        "# Regenerate with `dumpa update-signatures --db trackercontrol`. Curated",
        "# `trackers.toml` stays authoritative; on overlap the curated rule wins.",
        "",
        "[bundle]",
        f'name = "{const_bundle_name}"',
        f'version = "{version}"',
        f"source = {_toml_basic(const_source)}",
        f'updated = "{fetched}"',
        f"license = {_toml_basic(const_license)}",
        "",
    ])
    return header + ("\n" + body + "\n" if body else "")
