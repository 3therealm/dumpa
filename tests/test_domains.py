"""Domain Intelligence match logic (core/domains.py)."""

from __future__ import annotations

import pytest

from dumpa.core.domains import (
    DomainOwner,
    DomainTable,
    attribute,
    is_ip_literal,
    is_under_shared_infra,
    registrable_domain,
    validate_host,
)
from dumpa.core.errors import ConfigError


def _owner(owner: str = "Acme", subject: str | None = None) -> DomainOwner:
    return DomainOwner(owner=owner, category="analytics", subject=subject,
                       source="test", version="1")


# --- validate_host -----------------------------------------------------------

def test_validate_host_normalizes() -> None:
    assert validate_host("App-Measurement.COM.") == "app-measurement.com"
    assert validate_host("a.b.co.uk") == "a.b.co.uk"
    assert validate_host("a.b.co.uk.") == "a.b.co.uk"  # multi-label trailing dot


def test_validate_host_rejects_surrounding_whitespace() -> None:
    with pytest.raises(ConfigError):
        validate_host("  x.com  ")


@pytest.mark.parametrize("bad", [
    "a..com",          # empty label
    "-lead.com",       # leading hyphen
    "trail-.com",      # trailing hyphen
    "http://x.com",    # scheme
    "x.com/path",      # path
    "x.*",             # wildcard
    "",                # empty
    "single",          # one label
])
def test_validate_host_rejects(bad: str) -> None:
    with pytest.raises(ConfigError):
        validate_host(bad)


def test_validate_host_rejects_overlong_label() -> None:
    with pytest.raises(ConfigError):
        validate_host("a" * 64 + ".com")


# --- registrable_domain ------------------------------------------------------

def test_registrable_default_last_two() -> None:
    assert registrable_domain("a.appsflyer.com") == "appsflyer.com"


def test_registrable_cctld_suffix() -> None:
    assert registrable_domain("bbc.co.uk") == "bbc.co.uk"
    assert registrable_domain("a.bbc.co.uk") == "bbc.co.uk"


def test_registrable_private_paas_suffix() -> None:
    assert registrable_domain("tenant.github.io") == "tenant.github.io"
    # two different tenants -> two different registrable domains
    assert registrable_domain("a.github.io") != registrable_domain("b.github.io")


# --- is_under_shared_infra ---------------------------------------------------

@pytest.mark.parametrize("host", [
    "firebaseio.com", "x.firebaseio.com",
    "tenant.github.io", "d.cloudfront.net", "b.s3.amazonaws.com",
])
def test_shared_infra_true(host: str) -> None:
    assert is_under_shared_infra(host) is True


def test_shared_infra_false() -> None:
    assert is_under_shared_infra("appsflyer.com") is False


# --- is_ip_literal -----------------------------------------------------------

def test_is_ip_literal() -> None:
    assert is_ip_literal("203.0.113.5") is True
    assert is_ip_literal("example.com") is False
    assert is_ip_literal("256.1.1.1") is False  # out-of-range octet


def test_resolve_shared_infra_exact_only() -> None:
    # Security-critical: a shared-infra declared host must not attribute subdomains.
    table = DomainTable({"github.io": _owner("Should-Not-Leak")})
    assert table.resolve("a.github.io") is None
    got = table.resolve("github.io")
    assert got is not None and got.owner == "Should-Not-Leak"


# --- attribute ---------------------------------------------------------------

def test_attribute_exact() -> None:
    assert attribute("app.adjust.com", "app.adjust.com") is True


def test_attribute_suffix() -> None:
    assert attribute("gcdsdk.appsflyer.com", "appsflyer.com") is True


def test_attribute_substring_rejected() -> None:
    assert attribute("notappsflyer.com", "appsflyer.com") is False


def test_attribute_shared_infra_exact_only() -> None:
    assert attribute("a.firebaseio.com", "firebaseio.com") is False
    assert attribute("firebaseio.com", "firebaseio.com") is True


def test_attribute_ip_observed() -> None:
    assert attribute("203.0.113.5", "appsflyer.com") is False


# --- DomainTable.resolve -----------------------------------------------------

def test_resolve_longest_declared_wins() -> None:
    table = DomainTable({
        "x.com": _owner("Broad"),
        "events.x.com": _owner("Narrow"),
    })
    got = table.resolve("events.x.com")
    assert got is not None and got.owner == "Narrow"


def test_resolve_exact_beats_suffix() -> None:
    table = DomainTable({
        "appsflyer.com": _owner("AppsFlyer"),
    })
    got = table.resolve("gcdsdk.appsflyer.com")
    assert got is not None and got.owner == "AppsFlyer"
    exact = table.resolve("appsflyer.com")
    assert exact is not None and exact.owner == "AppsFlyer"


def test_resolve_empty_table() -> None:
    assert DomainTable({}).resolve("anything.com") is None
