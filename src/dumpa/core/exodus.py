"""Import the Exodus Privacy tracker database into a dumpa rule bundle.

Exodus publishes ~450 tracker signatures (https://exodus-privacy.eu.org). Each record
carries a ``code_signature`` (a regex of Java class-path prefixes — dots match the
slash-form descriptors in dex, which is why the signature works verbatim) and a
``network_signature`` (a regex of endpoint domains). This module is a *pure transform*:
parsed Exodus records -> a TOML rule bundle string, no network and no disk I/O, so it is
trivially testable. The networked fetch + write lives in ``commands.update_signatures``.

Mapping (see ROADMAP Phase 5 + the Exodus-import design):

- ``code_signature`` -> a ``regex`` tracker rule (verbatim).
- ``network_signature`` -> a second ``regex`` tracker rule with the same subject (the
  scanner merges by subject). It is a regex, not a literal-host ``domains`` rule, because
  Exodus network signatures are regexes; endpoint extraction + domain attribution already
  map observed hosts to owners separately.
- ``name`` -> ``subject``; ``website`` registrable domain -> ``owner`` (mechanical, no
  vendor-name normalization); ``categories`` -> the dumpa taxonomy (unmapped -> analytics).
- All imported rules are ``confidence = "medium"`` — broader and less hand-verified than
  the curated bundle, which stays authoritative (curated wins on overlap at scan time).

Every signature is compiled here; an invalid or trivially-broad one is dropped (logged),
so one bad upstream entry can never break the whole bundle at load time.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any
from urllib.parse import urlsplit

from dumpa.core.domains import registrable_domain

logger = logging.getLogger("dumpa")

const_exodus_url = "https://reports.exodus-privacy.eu.org/api/trackers/"
const_bundle_name = "trackers-exodus"
const_source = f"Exodus Privacy ({const_exodus_url})"
const_license = "Exodus Privacy tracker data — see https://exodus-privacy.eu.org (AGPL-3.0 project)"
const_confidence = "medium"
const_min_signature_len = 5     # drop trivially-broad signatures (e.g. "." matches everything)

# Exodus category label (lowercased) -> dumpa tracker taxonomy.
const_category_map = {
    "advertisement": "ads",
    "analytics": "analytics",
    "crash reporting": "crash reporting",
    "identification": "attribution",
    "profiling": "analytics",
    "location": "analytics",
}
# When a tracker carries several categories, the highest-priority mapped one wins.
const_category_priority = (
    "ads", "ad mediation", "attribution", "crash reporting",
    "push messaging", "remote config", "social login or sharing", "analytics",
)
const_default_category = "analytics"


def _records(data: Any) -> list[dict[str, Any]]:
    """Normalize the Exodus payload to a list of tracker dicts.

    Accepts the full API object ``{"trackers": {...}}``, a bare ``{"<id>": {...}}`` map,
    or an already-extracted list.
    """
    if isinstance(data, dict):
        inner = data.get("trackers", data)
        if isinstance(inner, dict):
            return [v for v in inner.values() if isinstance(v, dict)]
        if isinstance(inner, list):
            return [v for v in inner if isinstance(v, dict)]
    if isinstance(data, list):
        return [v for v in data if isinstance(v, dict)]
    return []


def _category(raw_categories: Any) -> str:
    mapped = set()
    if isinstance(raw_categories, list):
        for c in raw_categories:
            if isinstance(c, str):
                hit = const_category_map.get(c.strip().lower())
                if hit:
                    mapped.add(hit)
    for cat in const_category_priority:
        if cat in mapped:
            return cat
    return const_default_category


def _owner(website: Any) -> str:
    if not isinstance(website, str) or not website.strip():
        return ""
    host = urlsplit(website if "//" in website else f"//{website}").hostname or ""
    if not host:
        return ""
    try:
        return registrable_domain(host)
    except ValueError:
        return ""


def _valid_signature(sig: Any) -> str | None:
    """A usable regex source: non-empty, not trivially broad, and individually compilable."""
    if not isinstance(sig, str):
        return None
    sig = sig.strip()
    if len(sig) < const_min_signature_len:
        return None
    try:
        re.compile(sig.encode())
    except re.error:
        logger.debug("exodus import: dropping uncompilable signature %r", sig)
        return None
    return sig


def _toml_basic(s: str) -> str:
    """Escape a string into a TOML basic (double-quoted) string — safe for regex sources."""
    out = s.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{out}"'


def _rule_block(subject: str, *, regex: str, category: str, owner: str) -> str:
    lines = [
        "[[rule]]",
        'kind = "tracker"',
        f"subject = {_toml_basic(subject)}",
        f"category = {_toml_basic(category)}",
        f'confidence = "{const_confidence}"',
    ]
    if owner:
        lines.append(f"owner = {_toml_basic(owner)}")
    lines.append(f"regex = [{_toml_basic(regex)}]")
    return "\n".join(lines)


def exodus_records_to_bundle_toml(data: Any, *, fetched: str) -> str:
    """Transform parsed Exodus records into a dumpa rule-bundle TOML string.

    ``fetched`` is the import date (YYYY-MM-DD), recorded as ``[bundle].updated``. The
    bundle ``version`` is ``exodus.<count>.<hash8>`` over the emitted rule content, so
    re-importing identical upstream data yields an identical version — and therefore does
    not spuriously bust the per-scanner content cache.
    """
    blocks: list[str] = []
    subjects = 0
    for rec in _records(data):
        name = rec.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        subject = name.strip()
        category = _category(rec.get("categories"))
        owner = _owner(rec.get("website"))
        rules_for_subject = []
        for key in ("code_signature", "network_signature"):
            sig = _valid_signature(rec.get(key))
            if sig is not None:
                rules_for_subject.append(
                    _rule_block(subject, regex=sig, category=category, owner=owner))
        if not rules_for_subject:
            continue
        subjects += 1
        blocks.extend(rules_for_subject)

    body = "\n\n".join(blocks)
    digest = hashlib.sha256(body.encode()).hexdigest()[:8]
    version = f"exodus.{subjects}.{digest}"
    header = "\n".join([
        "# Imported Exodus Privacy tracker signatures (generated — do not edit by hand).",
        "# Regenerate with `dumpa update-signatures`. Curated `trackers.toml` stays",
        "# authoritative; on overlap the curated rule wins (class-path dedup at scan time).",
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
