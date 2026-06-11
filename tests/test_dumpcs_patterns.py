"""Tests for the dump.cs pattern-matching feature: rules extension, game-type
resolution, the Play store lookup, and the dumpcs scanner."""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from dumpa.core import gametype, playstore
from dumpa.core.config import (
    const_env_auto_dump,
    const_env_play_lookup,
    load_config,
)
from dumpa.core.report import AppFacts
from dumpa.core.rules import RuleBundle, load_builtin, load_bundle, scan_content_rules
from dumpa.core.workspace import Workspace
from dumpa.scanners import dumpcs
from dumpa.scanners import gametype as gametype_scanner

UTC = datetime.UTC


# --- rules engine: case-insensitivity, game_types, rooted scanning ----------

def _write_bundle(tmp_path: Path, body: str) -> RuleBundle:
    p = tmp_path / "b.toml"
    p.write_text(body, encoding="UTF-8")
    return load_bundle(p)


def test_case_insensitive_flag_parsed_and_applied(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, """
[bundle]
name = "t"
version = "1"
source = "t"
updated = "2026-06-08"
default_targets = ["dump.cs"]

[[rule]]
kind = "dumpcs"
subject = "ci"
confidence = "medium"
case_insensitive = true
regex = ['currencymanager']
""")
    rule = bundle.rules[0]
    assert rule.case_insensitive is True
    root = tmp_path / "dumps"
    root.mkdir()
    (root / "dump.cs").write_text("public class CurrencyManager {}", encoding="UTF-8")
    findings = scan_content_rules(list(bundle.rules), bundle, root)
    assert [f.subject for f in findings] == ["ci"]
    assert findings[0].locations[0].file_path == "dump.cs"


def test_case_sensitive_default_does_not_match_other_case(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, """
[bundle]
name = "t"
version = "1"
source = "t"
updated = "2026-06-08"
default_targets = ["dump.cs"]

[[rule]]
kind = "dumpcs"
subject = "cs"
confidence = "medium"
regex = ['currencymanager']
""")
    assert bundle.rules[0].case_insensitive is False
    root = tmp_path / "dumps"
    root.mkdir()
    (root / "dump.cs").write_text("class CurrencyManager {}", encoding="UTF-8")
    assert scan_content_rules(list(bundle.rules), bundle, root) == []


def test_game_types_parsed() -> None:
    assert load_builtin("dumpcs_match3").rules[0].game_types == ("match3",)
    assert load_builtin("dumpcs_general").rules[0].game_types == ()


def test_case_insensitive_must_be_bool(tmp_path: Path) -> None:
    from dumpa.core.errors import ConfigError
    with pytest.raises(ConfigError):
        _write_bundle(tmp_path, """
[bundle]
name = "t"
version = "1"
source = "t"
updated = "2026-06-08"

[[rule]]
kind = "dumpcs"
subject = "x"
confidence = "medium"
case_insensitive = "yes"
regex = ['a']
""")


# --- game-type map ----------------------------------------------------------

def test_genre_map_known_and_unknown() -> None:
    assert gametype._categories_for("GAME_PUZZLE") == ("match3",)
    assert gametype._categories_for("GAME_ROLE_PLAYING") == ("rpg",)
    assert gametype._categories_for("GAME_UNLISTED_XYZ") == ()


# --- playstore lookup -------------------------------------------------------

_LISTING_HTML = (
    '<a class="x" href="/store/apps/category/GAME_PUZZLE">'
    '<span itemprop="genre">Puzzle</span></a>'
)


def test_parse_listing_extracts_genre() -> None:
    listing = playstore._parse_listing(_LISTING_HTML, "com.x.y", "http://u", "2026-06-08T00:00:00+00:00")
    assert listing is not None
    assert listing.genre_id == "GAME_PUZZLE"
    assert listing.genre == "Puzzle"


def test_parse_listing_label_fallback_from_id() -> None:
    html = '<a href="/store/apps/category/GAME_ROLE_PLAYING">x</a>'
    listing = playstore._parse_listing(html, "com.x.y", "http://u", "t")
    assert listing is not None
    assert listing.genre == "Role Playing"


def test_parse_listing_none_when_no_genre() -> None:
    assert playstore._parse_listing("<html>nope</html>", "com.x.y", "u", "t") is None


def test_invalid_package_skips_lookup(tmp_path: Path) -> None:
    assert playstore.fetch_listing("not a package!", cache_dir=tmp_path,
                                   allow_network=True, timeout=5) is None


def test_offline_cache_miss_returns_none(tmp_path: Path) -> None:
    assert playstore.fetch_listing("com.x.y", cache_dir=tmp_path,
                                   allow_network=False, timeout=5) is None


def test_cache_hit_skips_network(tmp_path: Path) -> None:
    now = datetime.datetime(2026, 6, 8, tzinfo=UTC)
    listing = playstore.PlayListing("com.x.y", "Puzzle", "GAME_PUZZLE", "u", now.isoformat())
    playstore._write_cache(tmp_path, listing)
    # allow_network=False proves the result came from cache, not the wire.
    got = playstore.fetch_listing("com.x.y", cache_dir=tmp_path, allow_network=False,
                                  timeout=5, now=now)
    assert got is not None and got.genre_id == "GAME_PUZZLE"


def test_cache_expired_by_ttl(tmp_path: Path) -> None:
    old = datetime.datetime(2026, 1, 1, tzinfo=UTC)
    now = datetime.datetime(2026, 6, 8, tzinfo=UTC)
    playstore._write_cache(tmp_path, playstore.PlayListing(
        "com.x.y", "Puzzle", "GAME_PUZZLE", "u", old.isoformat()))
    assert playstore.fetch_listing("com.x.y", cache_dir=tmp_path, allow_network=False,
                                   timeout=5, ttl_days=30, now=now) is None


def test_fetch_network_path_with_stubbed_html(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(playstore, "_fetch_html", lambda url, timeout: _LISTING_HTML)
    now = datetime.datetime(2026, 6, 8, tzinfo=UTC)
    got = playstore.fetch_listing("com.x.y", cache_dir=tmp_path, allow_network=True,
                                  timeout=5, now=now)
    assert got is not None and got.genre_id == "GAME_PUZZLE"
    # and it was cached
    assert (tmp_path / "com.x.y.json").is_file()


# --- gametype resolution + sidecar ------------------------------------------

def test_resolve_reads_sidecar_first(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path)
    ws.dumps_dir.mkdir(parents=True)
    gt = gametype.GameType("Puzzle", "GAME_PUZZLE", ("match3",), "u", "t")
    ws.gametype_sidecar.write_text(json.dumps([gt.to_dict()]), encoding="UTF-8")
    got = gametype.resolve_game_types(ws, allow_network=False, timeout=5, ttl_days=30)
    assert [g.genre_id for g in got] == ["GAME_PUZZLE"]
    assert got[0].categories == ("match3",)


def test_resolve_no_manifest_writes_empty_sidecar(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path)
    ws.extracted_dir.mkdir(parents=True)
    got = gametype.resolve_game_types(ws, allow_network=False, timeout=5, ttl_days=30)
    assert got == []
    assert ws.gametype_sidecar.is_file()  # memoized so the lookup happens once


# --- dumpcs scanner ---------------------------------------------------------

def _seed_dump(ws: Workspace, text: str) -> None:
    ws.dumps_dir.mkdir(parents=True, exist_ok=True)
    (ws.dumps_dir / "dump.cs").write_text(text, encoding="UTF-8")


def _seed_categories(ws: Workspace, categories: tuple[str, ...]) -> None:
    gt = gametype.GameType("g", "GAME_X", categories, "u", "t")
    ws.gametype_sidecar.write_text(json.dumps([gt.to_dict()]), encoding="UTF-8")


def test_dumpcs_no_dump_is_noop(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path)
    ws.dumps_dir.mkdir(parents=True)
    assert dumpcs.scan(ws) == []


def test_dumpcs_always_on_runs_without_genre(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path)
    _seed_dump(ws, "public class PlayerManager {}\npublic class IntegrityChecker {}")
    _seed_categories(ws, ())   # no genre categories
    subjects = {f.subject for f in dumpcs.scan(ws)}
    assert "player-manager" in subjects       # general (always-on)
    assert "integrity-check" in subjects       # anti-cheat (always-on)


def test_dumpcs_genre_selects_match3(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path)
    _seed_dump(ws, "class GemManager {}\nclass CoinManager {}")
    # without the match3 category, the currency rules must not fire
    _seed_categories(ws, ())
    assert {f.subject for f in dumpcs.scan(ws)} & {"currency-hard", "currency-soft"} == set()
    # with match3 selected, they do
    _seed_categories(ws, ("match3",))
    subjects = {f.subject for f in dumpcs.scan(ws)}
    assert "currency-hard" in subjects
    assert "currency-soft" in subjects


def test_dumpcs_findings_carry_offset_and_version(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path)
    _seed_dump(ws, "xxxxxclass GemManager {}")   # "Gem" begins at byte 11
    _seed_categories(ws, ("match3",))
    hit = next(f for f in dumpcs.scan(ws) if f.subject == "currency-hard")
    loc = hit.locations[0]
    assert loc.file_path == "dump.cs"
    assert loc.file_offset == 11
    assert hit.evidence[0].rule_version == load_builtin("dumpcs_match3").version


# --- gametype scanner -------------------------------------------------------

def test_gametype_scanner_emits_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # play_lookup is forced off by conftest; sidecar supplies the resolved genre.
    ws = Workspace(root=tmp_path)
    gt = gametype.GameType("Puzzle", "GAME_PUZZLE", ("match3",), "http://u", "2026-06-08")
    ws.dumps_dir.mkdir(parents=True)
    ws.gametype_sidecar.write_text(json.dumps([gt.to_dict()]), encoding="UTF-8")
    findings = gametype_scanner.scan(ws)
    assert [f.subject for f in findings] == ["Puzzle"]
    assert findings[0].attributes["genre_id"] == "GAME_PUZZLE"
    assert findings[0].attributes["categories"] == "match3"


# --- report model + config --------------------------------------------------

def test_appfacts_game_types_roundtrip() -> None:
    facts = AppFacts(input_sha256="a", input_size=1, game_types=["Puzzle", "Casual"])
    back = AppFacts.from_dict(facts.to_dict())
    assert back.game_types == ["Puzzle", "Casual"]


def test_appfacts_game_types_default_empty_on_old_report() -> None:
    facts = AppFacts.from_dict({"input_sha256": "a", "input_size": 1})
    assert facts.game_types == []


def test_config_analysis_defaults_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(const_env_play_lookup, raising=False)
    cfg = load_config().analysis
    assert cfg.auto_dump is True
    assert cfg.play_lookup is True
    monkeypatch.setenv(const_env_play_lookup, "0")
    monkeypatch.setenv(const_env_auto_dump, "false")
    cfg2 = load_config().analysis
    assert cfg2.play_lookup is False
    assert cfg2.auto_dump is False
