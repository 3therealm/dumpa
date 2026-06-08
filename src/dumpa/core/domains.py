"""Domain Intelligence attribution match logic.

This module decides *whether an observed network host belongs to a declared SDK
domain*, owner-aware and shared-infrastructure-aware. It is pure string logic plus two
frozen data tables, with no I/O beyond the ownership-bundle loader (whose body lands in
the seed section).

`SHARED_INFRA` and `MULTI_LABEL_SUFFIXES` are deliberately **code, not TOML data**: they
are security-sensitive matching logic (a wrong entry causes mass false attribution), so
they are versioned and unit-tested alongside the algorithms that consume them.
"""

from __future__ import annotations

import importlib.resources
import logging
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from dumpa.core.errors import ConfigError

logger = logging.getLogger("dumpa")

const_data_package = "dumpa.data"
const_domains_filename = "domains.toml"

# Multi-tenant hosts that must NEVER attribute via suffix; an observed host under one of
# these is shared platform infrastructure, not a tracker signal, so it attributes only on
# an exact host match.
SHARED_INFRA: frozenset[str] = frozenset({
    "firebaseio.com", "googleapis.com", "gstatic.com", "fbcdn.net",
    "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "akamaihd.net",
    "azureedge.net", "cloudflare.com", "fastly.net", "appspot.com",
    "herokuapp.com", "web.app", "firebaseapp.com", "github.io",
    "isnssdk.com", "byteoversea.com", "ibytedtos.com",
})

# Public/private suffixes with more than one label, used to compute the registrable domain
# (eTLD+1) without a Public Suffix List. Keeps `a.github.io` and `b.github.io` distinct.
MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset({
    "co.uk", "com.br", "co.jp", "com.au", "co.in", "com.cn",
    "github.io", "firebaseapp.com", "web.app", "appspot.com",
    "herokuapp.com", "cloudfront.net", "s3.amazonaws.com", "azureedge.net",
})

_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}", re.ASCII)
# Sorted once: registrable_domain tries the longest multi-label suffix first.
_SORTED_SUFFIXES = tuple(sorted(MULTI_LABEL_SUFFIXES, key=len, reverse=True))


def _normalize(host: str) -> str:
    """Lowercase + strip a single trailing dot (no validation)."""
    host = host.strip().lower()
    if host.endswith("."):
        host = host[:-1]
    return host


def validate_host(host: str) -> str:
    """Normalize + validate a bare host; raise ConfigError on a malformed one.

    Lowercases, strips a single trailing dot, then validates LABEL-BY-LABEL: each label
    1-63 chars, alnum + internal hyphens only (no leading/trailing '-'), no empty label
    (rejects 'a..com'), at least two labels, alphabetic TLD. Shared by the `domains`
    matcher and the domains.toml loader so validation is identical everywhere.
    """
    if not isinstance(host, str) or not host:
        raise ConfigError(f"invalid host: {host!r}")
    if host != host.strip():
        raise ConfigError(f"invalid host {host!r}: surrounding whitespace")
    norm = _normalize(host)
    if any(c in norm for c in ("/", "*", ":", " ", "\t", "\x00")) or "://" in norm:
        raise ConfigError(f"invalid host {host!r}: illegal character")
    labels = norm.split(".")
    if len(labels) < 2:
        raise ConfigError(f"invalid host {host!r}: needs at least two labels")
    for label in labels:
        if not label or not _LABEL_RE.fullmatch(label):
            raise ConfigError(f"invalid host {host!r}: bad label {label!r}")
    if not labels[-1].isalpha():
        raise ConfigError(f"invalid host {host!r}: non-alphabetic TLD")
    return norm


def registrable_domain(host: str) -> str:
    """eTLD+1 of host without a Public Suffix List.

    Longest-suffix-wins over MULTI_LABEL_SUFFIXES (longest first); default = last two
    labels. Pure string logic.
    """
    norm = _normalize(host)
    for suffix in _SORTED_SUFFIXES:
        if norm == suffix or norm.endswith("." + suffix):
            rest = norm[: -len(suffix)].rstrip(".")
            if not rest:
                return norm
            left = rest.rsplit(".", 1)[-1]
            return f"{left}.{suffix}"
    labels = norm.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else norm


def is_under_shared_infra(host: str) -> bool:
    """True if the RAW host is, or is a subdomain of, any SHARED_INFRA entry.

    A suffix test on the raw host (not on registrable_domain(host), whose value for
    'tenant.github.io' is 'tenant.github.io' and would escape the denylist).
    """
    norm = _normalize(host)
    return any(norm == s or norm.endswith("." + s) for s in SHARED_INFRA)


def is_ip_literal(host: str) -> bool:
    """True for an IPv4 dotted-quad. Such hosts are never attributed."""
    norm = _normalize(host)
    if not _IPV4_RE.fullmatch(norm):
        return False
    return all(0 <= int(part) <= 255 for part in norm.split("."))


def attribute(observed_host: str, declared: str) -> bool:
    """Does observed_host belong to declared domain?

    1. IP/host-less observed_host -> False.
    2. If either side is shared infrastructure -> exact-host match only.
    3. Else label-boundary suffix match: observed == declared or endswith('.' + declared).
    Never raw substring (so 'notappsflyer.com' does NOT match 'appsflyer.com').
    """
    observed = _normalize(observed_host)
    declared = _normalize(declared)
    if not observed or is_ip_literal(observed):
        return False
    if is_under_shared_infra(declared) or is_under_shared_infra(observed):
        return observed == declared
    return observed == declared or observed.endswith("." + declared)


@dataclass(frozen=True)
class DomainOwner:
    """Who owns a declared domain, plus provenance."""
    owner: str
    category: str
    subject: str | None        # links to a tracker finding subject when known
    source: str                # bundle name (provenance)
    version: str               # bundle version (provenance)


@dataclass(frozen=True)
class DomainBundle:
    """Parsed [bundle] provenance + declared (host -> DomainOwner) entries from a
    domains.toml. Mirrors the RuleBundle provenance shape (name/version/source/updated)."""
    name: str
    version: str
    source: str
    updated: str
    owners: tuple[tuple[str, DomainOwner], ...]   # (host, owner) pairs, host validate_host'd


class DomainTable:
    """Lookup of declared host -> DomainOwner, built from all ownership sources.

    Resolution picks the LONGEST declared host that attribute()-matches the observed host
    (an exact match is the longest possible, so exact beats suffix). Construction merges,
    in precedence order: trackers-bundle domain rules, data/domains.toml seed, user bundle.
    """

    def __init__(self, owners: dict[str, DomainOwner]) -> None:
        self._owners: dict[str, DomainOwner] = {
            _normalize(host): owner for host, owner in owners.items()
        }

    def __len__(self) -> int:
        return len(self._owners)

    def resolve(self, observed_host: str) -> DomainOwner | None:
        observed = _normalize(observed_host)
        if not observed or is_ip_literal(observed):
            return None
        best: str | None = None
        for declared in self._owners:
            if attribute(observed, declared) and (best is None or len(declared) > len(best)):
                best = declared
        return self._owners[best] if best is not None else None


def _require_str(table: dict[str, Any], key: str, ctx: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{ctx}: missing or non-string {key!r}")
    return value


def _parse_domain_entry(raw: object, index: int, *, name: str, version: str) -> tuple[str, DomainOwner]:
    """One [[domain]] table -> (validated host, DomainOwner). Raises ConfigError if malformed."""
    if not isinstance(raw, dict):
        raise ConfigError(f"domain #{index}: must be a table")
    table = cast("dict[str, Any]", raw)
    ctx = f"domain #{index}"
    host = validate_host(_require_str(table, "host", ctx))
    owner = _require_str(table, "owner", ctx)
    category = _require_str(table, "category", ctx)
    subject = table.get("subject")
    if subject is not None and (not isinstance(subject, str) or not subject):
        raise ConfigError(f"{ctx}: 'subject' must be a non-empty string when present")
    return host, DomainOwner(owner=owner, category=category, subject=subject,
                             source=name, version=version)


def _parse_domains_toml(
    data: dict[str, Any], *, default_source: str
) -> tuple[str, str, str, str, dict[str, DomainOwner]]:
    """Parse a domains.toml dict into (name, version, source, updated, owners).

    Mirrors the [bundle] provenance discipline of core.rules._parse_bundle.
    """
    bundle_tbl = data.get("bundle")
    if not isinstance(bundle_tbl, dict):
        raise ConfigError("domains bundle: missing [bundle] table")
    bundle_tbl = cast("dict[str, Any]", bundle_tbl)
    name = _require_str(bundle_tbl, "name", "[bundle]")
    version = _require_str(bundle_tbl, "version", "[bundle]")
    updated = _require_str(bundle_tbl, "updated", "[bundle]")
    src = bundle_tbl.get("source")
    source = src if isinstance(src, str) and src else default_source

    domains_raw = data.get("domain", [])
    if not isinstance(domains_raw, list):
        raise ConfigError("domains bundle: [[domain]] must be an array of tables")
    owners: dict[str, DomainOwner] = {}
    for i, entry in enumerate(cast("list[object]", domains_raw)):
        host, owner = _parse_domain_entry(entry, i, name=name, version=version)
        owners[host] = owner
    return name, version, source, updated, owners


def _user_domains_path() -> Path:
    """User override bundle: $XDG_CONFIG_HOME/dumpa/domains.toml (fallback ~/.config)."""
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "dumpa" / "domains.toml"


def load_domains_bundle() -> DomainBundle:
    """Load the in-repo data/domains.toml seed, then merge an optional user bundle.

    Seed: importlib.resources.files("dumpa.data") / "domains.toml" (always present;
          a broken seed is a packaging bug and may raise).
    User bundle: $XDG_CONFIG_HOME/dumpa/domains.toml (fallback ~/.config/dumpa/domains.toml).
    Merge: user entries override/extend per host (user precedence). A malformed user bundle
           (bad TOML, missing [bundle], or a host failing validate_host) is logged at debug
           and IGNORED — it never crashes a report; the seed still loads.
    Each entry's `host` is normalized through validate_host; `owner`/`category` are required
    non-empty strings; `subject` is optional.

    Future (design only, not implemented): `dumpa update-signatures --domains
    --from {tracker-radar|exodus} <local-dir>` would convert a user's locally-downloaded
    dataset into a gitignored user bundle at this same $XDG_CONFIG_HOME path.
    """
    resource = importlib.resources.files(const_data_package) / const_domains_filename
    with resource.open("rb") as f:
        seed_data = tomllib.load(f)
    name, version, source, updated, owners = _parse_domains_toml(
        seed_data, default_source=f"builtin:{const_domains_filename}")

    user_path = _user_domains_path()
    if user_path.is_file():
        try:
            with user_path.open("rb") as f:
                user_data = tomllib.load(f)
            _, _, _, _, user_owners = _parse_domains_toml(
                user_data, default_source=str(user_path))
            owners.update(user_owners)  # user wins per host
        except (OSError, tomllib.TOMLDecodeError, ConfigError):
            logger.debug("ignoring malformed user domains bundle %s", user_path, exc_info=True)

    return DomainBundle(name=name, version=version, source=source, updated=updated,
                        owners=tuple(owners.items()))


def build_domain_table() -> DomainTable:
    """Assemble the DomainTable from all ownership sources.

    Precedence (low -> high): trackers-bundle `domains` rules, data/domains.toml seed,
    user bundle. Each declared host maps to a DomainOwner carrying its source bundle
    name/version for provenance. A missing/empty trackers source is treated as "no domain
    rules" so the table still works from the seed alone.
    """
    owners: dict[str, DomainOwner] = {}
    try:
        from dumpa.core.rules import load_builtin
        trackers = load_builtin("trackers")
        domain_rules = trackers.domain_rules() if hasattr(trackers, "domain_rules") else ()
        for rule in domain_rules:
            for host in rule.domains:
                owners[host] = DomainOwner(
                    owner=rule.attributes.get("owner", ""),
                    category=rule.attributes.get("category", ""),
                    subject=rule.subject,
                    source=trackers.name, version=trackers.version,
                )
    except (ConfigError, OSError):
        logger.debug("no trackers-bundle domain rules available", exc_info=True)

    bundle = load_domains_bundle()
    owners.update(dict(bundle.owners))  # seed (+ user, already merged) override trackers
    return DomainTable(owners)
