"""Tests for the `dumpa rewrite` engine (core/rewrite.py) and its rule extension."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from dumpa.core.errors import ConfigError, DumpaError
from dumpa.core.rewrite import (
    apply_edits,
    parse_selection,
    plan_edits,
    rewrite_rules_from_bundle,
)
from dumpa.core.rules import _parse_bundle

# A bundle that redirects an analytics host inside a const-string, keeping the wrapper.
_REWRITE_TOML = """
[bundle]
name = "redirect-analytics"
version = "2026.06.1"
updated = "2026-06-08"

[[rule]]
kind = "rewrite"
subject = "point analytics host at localhost"
category = "endpoints"
confidence = "medium"
regex = ['(const-string [vp]\\d+, ")analytics\\.example\\.com(")']
replace = '\\g<1>127.0.0.1\\g<2>'
"""

# A match-only bundle (no replace template) — preview/inventory only.
_MATCH_ONLY_TOML = """
[bundle]
name = "find-debug"
version = "1"
updated = "2026-06-08"

[[rule]]
kind = "rewrite"
subject = "debug flag"
category = "debug-flags"
confidence = "low"
regex = ['sput-boolean [vp]\\d+, Lcom/app/BuildConfig;->DEBUG:Z']
"""


def _bundle(toml: str):
    return _parse_bundle(tomllib.loads(toml), default_source="test")


def _write_smali(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="latin-1")
    return path


# --- rule-model extension -------------------------------------------------------------

def test_rewrite_rule_parses_with_replace() -> None:
    bundle = _bundle(_REWRITE_TOML)
    rule = bundle.rules[0]
    assert rule.kind == "rewrite"
    assert rule.replace == "\\g<1>127.0.0.1\\g<2>"


def test_replace_rejected_on_non_rewrite_kind() -> None:
    toml = _REWRITE_TOML.replace('kind = "rewrite"', 'kind = "tracker"')
    with pytest.raises(ConfigError, match="only valid on a kind='rewrite'"):
        _bundle(toml)


def test_replace_backref_out_of_range_rejected() -> None:
    toml = """
[bundle]
name = "bad"
version = "1"
updated = "2026-06-08"
[[rule]]
kind = "rewrite"
subject = "bad backref"
category = "x"
confidence = "low"
regex = ['(foo)(bar)']
replace = '\\g<5>x'
"""
    with pytest.raises(ConfigError, match="group"):
        _bundle(toml)


def test_match_only_bundle_has_no_replace() -> None:
    rule = _bundle(_MATCH_ONLY_TOML).rules[0]
    assert rule.replace == ""


# --- parse_selection ------------------------------------------------------------------

def test_select_all() -> None:
    assert parse_selection("all", 3) == {1, 2, 3}


def test_select_list_and_ranges() -> None:
    assert parse_selection("1-3,7", 7) == {1, 2, 3, 7}
    assert parse_selection("2,5", 5) == {2, 5}


def test_select_out_of_range_raises() -> None:
    with pytest.raises(ConfigError, match="out of range"):
        parse_selection("9", 3)


def test_select_reversed_range_raises() -> None:
    with pytest.raises(ConfigError, match="reversed range"):
        parse_selection("5-2", 9)


def test_select_garbage_raises() -> None:
    with pytest.raises(ConfigError, match="invalid token"):
        parse_selection("abc", 3)


# --- plan_edits -----------------------------------------------------------------------

def test_plan_assigns_stable_indices(tmp_path: Path) -> None:
    _write_smali(tmp_path, "a.smali", 'const-string v0, "analytics.example.com"\n')
    _write_smali(tmp_path, "b.smali", 'const-string v1, "analytics.example.com"\n')
    rules = rewrite_rules_from_bundle(_bundle(_REWRITE_TOML))
    p1 = plan_edits(tmp_path, rules)
    p2 = plan_edits(tmp_path, rules)
    assert [m.index for m in p1.matches] == [1, 2]
    # deterministic across runs (sorted by file: a before b)
    assert [m.file_rel for m in p1.matches] == ["a.smali", "b.smali"]
    assert [m.byte_offset for m in p1.matches] == [m.byte_offset for m in p2.matches]


def test_plan_populates_after_with_backref(tmp_path: Path) -> None:
    _write_smali(tmp_path, "a.smali", 'const-string v0, "analytics.example.com"\n')
    rules = rewrite_rules_from_bundle(_bundle(_REWRITE_TOML))
    m = plan_edits(tmp_path, rules).matches[0]
    assert m.before == 'const-string v0, "analytics.example.com"'
    assert m.after == 'const-string v0, "127.0.0.1"'


def test_plan_match_only_has_no_after(tmp_path: Path) -> None:
    _write_smali(tmp_path, "a.smali",
                 "sput-boolean v0, Lcom/app/BuildConfig;->DEBUG:Z\n")
    rules = rewrite_rules_from_bundle(_bundle(_MATCH_ONLY_TOML))
    m = plan_edits(tmp_path, rules).matches[0]
    assert m.after is None


def test_locator_single_vs_multi_per_line(tmp_path: Path) -> None:
    # two matches on one line -> both disambiguate with @col; lone match shows file:line
    _write_smali(tmp_path, "multi.smali",
                 'a "analytics.example.com" b "analytics.example.com"\n')
    _write_smali(tmp_path, "solo.smali", 'x "analytics.example.com"\n')
    # a looser rule that matches the bare host (one capture wrapper not needed here)
    toml = """
[bundle]
name = "host"
version = "1"
updated = "2026-06-08"
[[rule]]
kind = "rewrite"
subject = "host"
category = "endpoints"
confidence = "low"
regex = ['analytics\\.example\\.com']
replace = 'localhost'
"""
    rules = rewrite_rules_from_bundle(_bundle(toml))
    plan = plan_edits(tmp_path, rules)
    locators = {m.locator for m in plan.matches}
    assert "solo.smali:1" in locators
    assert any("@" in loc and loc.startswith("multi.smali") for loc in locators)


def test_category_filter_limits_rules(tmp_path: Path) -> None:
    _write_smali(tmp_path, "a.smali", 'const-string v0, "analytics.example.com"\n')
    rules = rewrite_rules_from_bundle(_bundle(_REWRITE_TOML))
    assert len(plan_edits(tmp_path, rules, categories=("endpoints",)).matches) == 1
    assert plan_edits(tmp_path, rules, categories=("ads",)).matches == ()


# --- apply_edits ----------------------------------------------------------------------

def test_apply_writes_substitution(tmp_path: Path) -> None:
    path = _write_smali(tmp_path, "a.smali",
                        'const-string v0, "analytics.example.com"\n')
    rules = rewrite_rules_from_bundle(_bundle(_REWRITE_TOML))
    plan = plan_edits(tmp_path, rules)
    edits = apply_edits(tmp_path, plan, {1}, rule_version="2026.06.1")
    assert len(edits) == 1
    assert path.read_text(encoding="latin-1") == 'const-string v0, "127.0.0.1"\n'


def test_apply_only_selected(tmp_path: Path) -> None:
    a = _write_smali(tmp_path, "a.smali", 'const-string v0, "analytics.example.com"\n')
    b = _write_smali(tmp_path, "b.smali", 'const-string v1, "analytics.example.com"\n')
    rules = rewrite_rules_from_bundle(_bundle(_REWRITE_TOML))
    plan = plan_edits(tmp_path, rules)
    apply_edits(tmp_path, plan, {1}, rule_version="1")
    assert "127.0.0.1" in a.read_text(encoding="latin-1")
    assert "analytics.example.com" in b.read_text(encoding="latin-1")  # untouched


def test_apply_right_to_left_length_change(tmp_path: Path) -> None:
    # two matches on one line; the replacement is shorter, so a naive left-to-right pass
    # would corrupt the second offset. Right-to-left must keep both correct.
    path = _write_smali(tmp_path, "a.smali",
                        '"analytics.example.com" "analytics.example.com"\n')
    toml = _REWRITE_TOML  # capture wrappers won't match bare; use a bare-host rule instead
    toml = """
[bundle]
name = "host"
version = "1"
updated = "2026-06-08"
[[rule]]
kind = "rewrite"
subject = "host"
category = "endpoints"
confidence = "low"
regex = ['analytics\\.example\\.com']
replace = 'x'
"""
    rules = rewrite_rules_from_bundle(_bundle(toml))
    plan = plan_edits(tmp_path, rules)
    apply_edits(tmp_path, plan, {1, 2}, rule_version="1")
    assert path.read_text(encoding="latin-1") == '"x" "x"\n'


def test_apply_match_only_raises(tmp_path: Path) -> None:
    _write_smali(tmp_path, "a.smali",
                 "sput-boolean v0, Lcom/app/BuildConfig;->DEBUG:Z\n")
    rules = rewrite_rules_from_bundle(_bundle(_MATCH_ONLY_TOML))
    plan = plan_edits(tmp_path, rules)
    with pytest.raises(DumpaError, match="no replacement"):
        apply_edits(tmp_path, plan, {1}, rule_version="1")


def test_no_rewrite_rules_raises() -> None:
    toml = """
[bundle]
name = "empty"
version = "1"
updated = "2026-06-08"
[[rule]]
kind = "tracker"
subject = "x"
confidence = "low"
strings = ["foo"]
"""
    with pytest.raises(ConfigError, match="no kind='rewrite' rules"):
        rewrite_rules_from_bundle(_bundle(toml))
