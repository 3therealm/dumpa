"""core.exodus: the pure Exodus-records -> rule-bundle TOML transform."""

from __future__ import annotations

import tomllib

from dumpa.core.exodus import exodus_records_to_bundle_toml
from dumpa.core.rules import load_bundle


def _load(data: object, tmp_path):
    text = exodus_records_to_bundle_toml(data, fetched="2026-06-08")
    p = tmp_path / "exodus.toml"
    p.write_text(text)
    return load_bundle(p), text


def test_both_signals_emit_two_rules_same_subject(tmp_path) -> None:
    data = {"trackers": {"1": {
        "name": "Adjust", "code_signature": "com.adjust.sdk.",
        "network_signature": "app.adjust.com", "website": "https://www.adjust.com/",
        "categories": ["Analytics"]}}}
    bundle, _ = _load(data, tmp_path)
    rules = [r for r in bundle.rules if r.subject == "Adjust"]
    assert len(rules) == 2
    assert all(r.kind == "tracker" and r.confidence.value == "medium" for r in rules)
    assert all(r.regex for r in rules)             # both signals map to regex rules


def test_category_priority_and_owner(tmp_path) -> None:
    data = {"trackers": {"1": {
        "name": "X", "code_signature": "com.x.sdk.", "network_signature": "",
        "website": "https://sub.example.co.uk/path", "categories": ["Analytics", "Advertisement"]}}}
    bundle, _ = _load(data, tmp_path)
    r = next(r for r in bundle.rules if r.subject == "X")
    assert r.attributes["category"] == "ads"            # Advertisement outranks Analytics
    assert r.attributes["owner"] == "example.co.uk"     # registrable domain of website


def test_unmapped_category_falls_back_to_analytics(tmp_path) -> None:
    data = {"trackers": {"1": {
        "name": "Y", "code_signature": "com.y.sdk.", "categories": ["Totally Unknown"]}}}
    bundle, _ = _load(data, tmp_path)
    r = next(r for r in bundle.rules if r.subject == "Y")
    assert r.attributes["category"] == "analytics"


def test_skips_empty_and_trivial_and_uncompilable(tmp_path) -> None:
    data = {"trackers": {
        "1": {"name": "NoSig", "code_signature": "", "network_signature": ""},
        "2": {"name": "Trivial", "code_signature": "."},          # too broad -> dropped
        "3": {"name": "Bad", "code_signature": "com.ok.sdk(["},   # uncompilable -> dropped
        "4": {"name": "Good", "code_signature": "com.good.sdk."},
    }}
    bundle, _ = _load(data, tmp_path)
    assert {r.subject for r in bundle.rules} == {"Good"}


def test_version_is_deterministic_for_same_data(tmp_path) -> None:
    data = {"trackers": {"1": {"name": "Z", "code_signature": "com.z.sdk."}}}
    v1 = tomllib.loads(exodus_records_to_bundle_toml(data, fetched="2026-06-08"))["bundle"]["version"]
    v2 = tomllib.loads(exodus_records_to_bundle_toml(data, fetched="2030-01-01"))["bundle"]["version"]
    assert v1 == v2                       # version keys on content, not the fetch date
    assert v1.startswith("exodus.1.")


def test_provenance_recorded(tmp_path) -> None:
    bundle, _ = _load({"trackers": {"1": {"name": "Z", "code_signature": "com.z.sdk."}}}, tmp_path)
    assert bundle.name == "trackers-exodus"
    assert "Exodus" in bundle.source
    assert bundle.license
    assert bundle.updated == "2026-06-08"
