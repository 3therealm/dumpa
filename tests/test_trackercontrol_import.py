"""core.trackercontrol: the pure xray-blacklist -> rule-bundle TOML transform."""

from __future__ import annotations

from dumpa.core.trackercontrol import trackercontrol_records_to_bundle_toml


def _load(data: object, tmp_path):
    from dumpa.core.rules import load_bundle
    text = trackercontrol_records_to_bundle_toml(data, fetched="2026-06-09")
    p = tmp_path / "tc.toml"
    p.write_text(text)
    return load_bundle(p), text


def test_hosts_become_one_tracker_rule_with_escaped_regexes(tmp_path) -> None:
    data = [{"owner_name": "Criteo", "doms": ["criteo.com", "criteo.net"],
             "parent": None, "root_parent": None}]
    bundle, _ = _load(data, tmp_path)
    rules = [r for r in bundle.rules if r.subject == "Criteo"]
    assert len(rules) == 1                             # one rule, multiple host regexes
    r = rules[0]
    assert r.kind == "tracker" and r.confidence.value == "medium"
    assert set(r.regex) == {r"criteo\.com", r"criteo\.net"}   # dots escaped to literals
    assert "category" not in r.attributes             # xray carries no purpose category


def test_owner_prefers_parent_company(tmp_path) -> None:
    data = [{"owner_name": "tynt", "doms": ["tynt.com"],
             "parent": "33Across", "root_parent": "33Across"}]
    bundle, _ = _load(data, tmp_path)
    r = next(r for r in bundle.rules if r.subject == "tynt")
    assert r.attributes["owner"] == "33Across"        # root_parent wins over the product name


def test_owner_falls_back_to_product_when_self_owned(tmp_path) -> None:
    data = [{"owner_name": "Criteo", "doms": ["criteo.com"], "parent": None, "root_parent": None}]
    bundle, _ = _load(data, tmp_path)
    r = next(r for r in bundle.rules if r.subject == "Criteo")
    assert r.attributes["owner"] == "Criteo"


def test_necessary_and_empty_records_are_skipped(tmp_path) -> None:
    data = [
        {"owner_name": "Necessary", "doms": ["needed.com"], "necessary": True},   # skipped
        {"owner_name": "NoDoms", "doms": []},                                     # skipped
        {"owner_name": "", "doms": ["anon.com"]},                                 # no subject
        {"owner_name": "Good", "doms": ["good.example.com"]},
    ]
    bundle, _ = _load(data, tmp_path)
    assert {r.subject for r in bundle.rules} == {"Good"}


def test_accepts_wrapper_and_map_shapes(tmp_path) -> None:
    wrapper = {"trackers": [{"owner_name": "W", "doms": ["w.com"]}]}
    as_map = {"trackers": {"1": {"owner_name": "M", "doms": ["m.com"]}}}
    assert {r.subject for r in _load(wrapper, tmp_path)[0].rules} == {"W"}
    assert {r.subject for r in _load(as_map, tmp_path)[0].rules} == {"M"}


def test_version_is_deterministic_for_same_data(tmp_path) -> None:
    data = [{"owner_name": "Z", "doms": ["z.com"]}]
    a = trackercontrol_records_to_bundle_toml(data, fetched="2026-06-09")
    b = trackercontrol_records_to_bundle_toml(data, fetched="2030-01-01")
    # version hashes the rule body, not the fetch date -> stable across re-imports.
    va = next(line for line in a.splitlines() if line.startswith("version"))
    vb = next(line for line in b.splitlines() if line.startswith("version"))
    assert va == vb and "trackercontrol.1." in va


def test_vendored_seed_parses(tmp_path, monkeypatch) -> None:
    # Isolate from any real user override so the in-repo vendored snapshot is what loads.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty"))
    from dumpa.core.rules import load_builtin
    bundle = load_builtin("trackers_trackercontrol")
    assert bundle.name == "trackers-trackercontrol"
    assert any(r.subject == "Criteo" for r in bundle.rules)
