"""Endpoint purpose classification.

Decides *what an observed endpoint is for* — a Firebase config fetch, a CDN download, an
ad-auction call — from its host and the URL paths seen on it. This is complementary to
`core.domains` attribution: `domains` answers "who owns this host" (tracker taxonomy);
this answers "what function does this endpoint serve", and it works even for hosts absent
from the ownership table (e.g. an OpenRTB auction path on an unknown host).

Data-driven, mirroring the `core.domains` precedent: a curated `dumpa/data/endpoints.toml`
seed plus an optional user override at `$XDG_CONFIG_HOME/dumpa/endpoints.toml`. Pure
string/regex logic; no I/O beyond the bundle loader.
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

from dumpa.core.domains import validate_host
from dumpa.core.errors import ConfigError

logger = logging.getLogger("dumpa")

const_data_package = "dumpa.data"
const_endpoints_filename = "endpoints.toml"


@dataclass(frozen=True)
class EndpointRule:
    """One purpose plus its matchers: host suffixes and/or URL-path regexes."""
    purpose: str
    hosts: tuple[str, ...]                 # label-boundary suffix match (bare hosts)
    url_patterns: tuple[re.Pattern[str], ...]


class EndpointTable:
    """Classifies (host, paths) -> purpose. Most-specific-wins.

    A URL-path pattern is more specific than a host suffix (an `/openrtb2/auction` path
    marks an ad auction regardless of host), so path rules are tried first; among host
    rules the longest declared suffix wins. Returns None when nothing matches.
    """

    def __init__(self, rules: tuple[EndpointRule, ...]) -> None:
        self._rules = rules

    def __len__(self) -> int:
        return len(self._rules)

    def classify(self, host: str, paths: tuple[str, ...]) -> str | None:
        for rule in self._rules:
            for pat in rule.url_patterns:
                if any(pat.search(p) for p in paths):
                    return rule.purpose
        host = host.strip().lower().rstrip(".")
        best: str | None = None
        best_len = -1
        for rule in self._rules:
            for declared in rule.hosts:
                if (host == declared or host.endswith("." + declared)) and len(declared) > best_len:
                    best, best_len = rule.purpose, len(declared)
        return best


def _require_str(table: dict[str, Any], key: str, ctx: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{ctx}: missing or non-string {key!r}")
    return value


def _parse_rule(raw: object, index: int) -> EndpointRule:
    if not isinstance(raw, dict):
        raise ConfigError(f"endpoint #{index}: must be a table")
    table = cast("dict[str, Any]", raw)
    ctx = f"endpoint #{index}"
    purpose = _require_str(table, "purpose", ctx)
    hosts_raw = table.get("hosts", [])
    pats_raw = table.get("url_patterns", [])
    if not isinstance(hosts_raw, list) or not isinstance(pats_raw, list):
        raise ConfigError(f"{ctx}: 'hosts'/'url_patterns' must be arrays")
    if not hosts_raw and not pats_raw:
        raise ConfigError(f"{ctx}: needs at least one of 'hosts' or 'url_patterns'")
    hosts = tuple(validate_host(cast("str", h)) for h in hosts_raw)
    try:
        patterns = tuple(re.compile(cast("str", p)) for p in pats_raw)
    except re.error as exc:
        raise ConfigError(f"{ctx}: bad url_pattern regex: {exc}") from exc
    return EndpointRule(purpose=purpose, hosts=hosts, url_patterns=patterns)


def _parse_endpoints_toml(data: dict[str, Any]) -> tuple[EndpointRule, ...]:
    bundle_tbl = data.get("bundle")
    if not isinstance(bundle_tbl, dict):
        raise ConfigError("endpoints bundle: missing [bundle] table")
    bundle_tbl = cast("dict[str, Any]", bundle_tbl)
    _require_str(bundle_tbl, "name", "[bundle]")
    _require_str(bundle_tbl, "version", "[bundle]")
    _require_str(bundle_tbl, "updated", "[bundle]")
    rules_raw = data.get("endpoint", [])
    if not isinstance(rules_raw, list):
        raise ConfigError("endpoints bundle: [[endpoint]] must be an array of tables")
    return tuple(_parse_rule(entry, i) for i, entry in enumerate(cast("list[object]", rules_raw)))


def _user_endpoints_path() -> Path:
    """User override bundle: $XDG_CONFIG_HOME/dumpa/endpoints.toml (fallback ~/.config)."""
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "dumpa" / const_endpoints_filename


def load_endpoint_rules() -> EndpointTable:
    """Load the in-repo data/endpoints.toml seed, then merge an optional user bundle.

    Seed: always present (a broken seed is a packaging bug and may raise). User bundle at
    $XDG_CONFIG_HOME/dumpa/endpoints.toml is appended (its rules tried after the seed); a
    malformed user bundle is logged at debug and IGNORED — it never crashes a report.
    """
    resource = importlib.resources.files(const_data_package) / const_endpoints_filename
    with resource.open("rb") as f:
        rules = list(_parse_endpoints_toml(tomllib.load(f)))

    user_path = _user_endpoints_path()
    if user_path.is_file():
        try:
            with user_path.open("rb") as f:
                rules.extend(_parse_endpoints_toml(tomllib.load(f)))
        except (OSError, tomllib.TOMLDecodeError, ConfigError):
            logger.debug("ignoring malformed user endpoints bundle %s", user_path, exc_info=True)

    return EndpointTable(tuple(rules))
