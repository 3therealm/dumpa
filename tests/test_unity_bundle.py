"""The `unity` rule bundle: loads, is listed, and does not overlap trackers.toml."""

from __future__ import annotations

from dumpa.core.rules import builtin_bundle_names, load_builtin


def test_unity_bundle_loads() -> None:
    bundle = load_builtin("unity")
    assert bundle.name == "unity"
    assert bundle.rules
    assert all(r.kind == "engine-detail" for r in bundle.rules)


def test_unity_bundle_listed() -> None:
    assert "unity" in builtin_bundle_names()


def test_no_overlap_with_trackers() -> None:
    """Dedup discipline: no unity rule may reuse a key already owned by trackers.toml."""
    unity_keys = {k for r in load_builtin("unity").rules for k in (*r.strings, *r.globs)}
    tracker_keys = {k for r in load_builtin("trackers").rules for k in (*r.strings, *r.globs)}
    assert not (unity_keys & tracker_keys), unity_keys & tracker_keys
