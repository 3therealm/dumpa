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

import re
from dataclasses import dataclass

from dumpa.core.errors import ConfigError

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


def load_domains_bundle() -> DomainBundle:
    """Load the in-repo data/domains.toml seed, then merge an optional user bundle.

    The body (seed read + user-bundle merge) is implemented in the seed section; this stub
    returns an empty bundle so the public surface is stable for earlier sections.
    """
    return DomainBundle(name="domains", version="0", source="builtin:domains",
                        updated="", owners=())


def build_domain_table() -> DomainTable:
    """Assemble the DomainTable from the ownership sources.

    Wired to the trackers-bundle domain rules + the seed in later sections; this stub
    assembles only from load_domains_bundle() so an empty table is valid and resolvable.
    """
    bundle = load_domains_bundle()
    return DomainTable(dict(bundle.owners))
