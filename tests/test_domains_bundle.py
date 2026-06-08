"""Domain-ownership seed + loader: load_domains_bundle / build_domain_table (C2)."""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.core.domains import (
    build_domain_table,
    is_under_shared_infra,
    load_domains_bundle,
    validate_host,
)
from dumpa.core.report import Confidence
from dumpa.core.rules import Rule, RuleBundle, builtin_bundle_names


def _write_user_bundle(tmp_path: Path, body: str) -> None:
    d = tmp_path / "dumpa"
    d.mkdir(parents=True, exist_ok=True)
    (d / "domains.toml").write_text(body)


# --- load_domains_bundle (seed) ---------------------------------------------

def test_load_seed_provenance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))  # no user bundle
    bundle = load_domains_bundle()
    assert bundle.name == "domains"
    assert bundle.version and bundle.source and bundle.updated
    assert len(bundle.owners) >= 1


# --- guard against rules-list crash -----------------------------------------

def test_domains_not_a_builtin_rule_bundle() -> None:
    assert "domains" not in builtin_bundle_names()


# --- user-bundle merge ------------------------------------------------------

def test_user_bundle_overrides_and_adds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    _write_user_bundle(tmp_path, """
[bundle]
name = "user"
version = "9"
updated = "2026-06-07"

[[domain]]
host = "app-measurement.com"
owner = "OverriddenOwner"
category = "analytics"

[[domain]]
host = "my-private-host.example"
owner = "MyCorp"
category = "analytics"
""")
    table = build_domain_table()
    overridden = table.resolve("app-measurement.com")
    assert overridden is not None and overridden.owner == "OverriddenOwner"
    added = table.resolve("my-private-host.example")
    assert added is not None and added.owner == "MyCorp"


@pytest.mark.parametrize("body", [
    "this is not valid toml {{{",
    # host fails validate_host
    """
[bundle]
name = "user"
version = "1"
updated = "2026-06-07"

[[domain]]
host = "http://bad/*"
owner = "X"
category = "analytics"
""",
    # missing [bundle] table
    """
[[domain]]
host = "ok.example"
owner = "X"
category = "analytics"
""",
])
def test_malformed_user_bundle_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    _write_user_bundle(tmp_path, body)
    # No exception propagates, and the seed still loads + resolves.
    table = build_domain_table()
    assert table.resolve("app-measurement.com") is not None


# --- seed integrity (audits the real shipped seed) --------------------------

def test_seed_hosts_valid_and_not_shared_infra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))  # isolate from any real user bundle
    bundle = load_domains_bundle()
    assert len(bundle.owners) >= 1
    for host, _owner in bundle.owners:
        assert validate_host(host) == host
        assert not is_under_shared_infra(host)


# --- table assembly ---------------------------------------------------------

def test_build_table_resolves_known_seed_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    table = build_domain_table()
    got = table.resolve("app-measurement.com")
    assert got is not None and got.owner == "Google"


# --- trackers-bundle merge + precedence -------------------------------------

def _fake_trackers(host: str, owner: str) -> RuleBundle:
    rule = Rule(kind="tracker", subject="Fake SDK", confidence=Confidence.LOW,
                domains=(host,), domain_search=True,
                attributes={"owner": owner, "category": "ads"})
    return RuleBundle(name="trackers", version="9", source="test",
                      updated="2026-06-08", rules=(rule,))


def test_build_table_includes_trackers_domain_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr("dumpa.core.rules.load_builtin",
                        lambda name: _fake_trackers("trackeronly.example", "TrackerCorp"))
    table = build_domain_table()
    got = table.resolve("trackeronly.example")  # host only in trackers, not the seed
    assert got is not None and got.owner == "TrackerCorp"


def test_seed_overrides_trackers_for_shared_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    # trackers claims app-measurement.com for a different owner; seed must win.
    monkeypatch.setattr("dumpa.core.rules.load_builtin",
                        lambda name: _fake_trackers("app-measurement.com", "TrackerCorp"))
    table = build_domain_table()
    got = table.resolve("app-measurement.com")
    assert got is not None and got.owner == "Google"


# --- rules list provenance line ---------------------------------------------

def test_rules_list_prints_domains_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    from dumpa.commands.rules import rules_list
    rules_list()
    out = capsys.readouterr().out
    domains_line = next((ln for ln in out.splitlines() if ln.startswith("domains:")), None)
    assert domains_line is not None and "domains=" in domains_line
