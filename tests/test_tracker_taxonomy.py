"""The curated trackers bundle ships the A/B-testing, anti-fraud, and consent categories."""

from __future__ import annotations

from dumpa.core.rules import load_builtin


def test_new_categories_present() -> None:
    rules = load_builtin("trackers").rules
    categories = {r.attributes.get("category") for r in rules}
    assert {"A/B testing", "anti-fraud", "consent management"} <= categories


def test_representative_sdks_present() -> None:
    subjects = {r.subject for r in load_builtin("trackers").rules}
    for sdk in ("Optimizely", "Forter", "OneTrust", "Google UMP", "Quantcast Choice"):
        assert sdk in subjects, sdk
