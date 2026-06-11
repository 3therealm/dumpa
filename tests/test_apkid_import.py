"""core.apkid: the pure APKiD-YARA -> protection rule-bundle TOML transform."""

from __future__ import annotations

from dumpa.core.apkid import apkid_rules_to_bundle_toml
from dumpa.core.rules import load_bundle


def _load(yara: str, tmp_path):
    text = apkid_rules_to_bundle_toml(yara, fetched="2026-06-09")
    p = tmp_path / "apkid.toml"
    p.write_text(text)
    return load_bundle(p), text


_JIAGU = """
// dumpa-apkid-source: packers/jiagu.yara
rule jiagu : packer
{
    meta:
        description = "Jiagu (360)"
    strings:
        $a = "libjiagu.so"
        $b = { 6A 69 61 67 75 }
    condition:
        any of them
}
"""


def test_mixed_kinds_any_split_into_per_kind_rules(tmp_path) -> None:
    bundle, _ = _load(_JIAGU, tmp_path)
    rules = [r for r in bundle.rules if r.subject == "Jiagu (360)"]
    assert len(rules) == 2                       # text strings + hex -> two rules
    assert {r.kind for r in rules} == {"protection"}
    assert all(r.attributes["category"] == "packer" for r in rules)
    assert all(r.confidence.value == "medium" for r in rules)
    assert any(r.strings == ("libjiagu.so",) for r in rules)
    assert any(r.bytes_hex == ("6A69616775",) for r in rules)


def test_compilers_and_unmapped_paths_are_dropped(tmp_path) -> None:
    yara = """
// dumpa-apkid-source: compilers/dx.yara
rule dx { strings: $a = "DX schema" condition: all of them }
// dumpa-apkid-source: abnormal/weird.yara
rule weird { strings: $a = "weird" condition: any of them }
"""
    text = apkid_rules_to_bundle_toml(yara, fetched="2026-06-09")
    assert "[[rule]]" not in text   # no category-bearing source path -> all dropped


def test_all_of_them_keeps_match_all_single_kind(tmp_path) -> None:
    yara = """
// dumpa-apkid-source: anti_debug/ptrace.yara
rule ptrace
{
    meta:
        description = "ptrace anti-debug"
    strings:
        $a = "ptrace"
        $b = "TracerPid"
    condition:
        dex.header and all of them
}
"""
    bundle, _ = _load(yara, tmp_path)
    r = next(r for r in bundle.rules if r.subject == "ptrace anti-debug")
    assert r.attributes["category"] == "anti-debug"
    assert r.match == "all"                      # leading format guard ignored, all-of kept
    assert set(r.strings) == {"ptrace", "TracerPid"}


def test_all_of_them_dropped_when_kinds_mixed(tmp_path) -> None:
    # An AND across a text string and a hex byte sig cannot be one matcher-kind rule -> drop.
    yara = """
// dumpa-apkid-source: protectors/mixed.yara
rule mixed
{
    strings:
        $a = "marker"
        $b = { AA BB CC }
    condition:
        all of them
}
"""
    text = apkid_rules_to_bundle_toml(yara, fetched="2026-06-09")
    assert "[[rule]]" not in text


def test_unportable_hex_and_wide_strings_dropped(tmp_path) -> None:
    yara = """
// dumpa-apkid-source: obfuscators/o.yara
rule o
{
    strings:
        $jump = { E8 ?? [4] FF }
        $wide = "secret" wide
    condition:
        any of them
}
"""
    text = apkid_rules_to_bundle_toml(yara, fetched="2026-06-09")
    assert "[[rule]]" not in text               # both strings un-portable -> rule dropped


def test_offset_condition_dropped(tmp_path) -> None:
    yara = """
// dumpa-apkid-source: packers/p.yara
rule p { strings: $a = "thing" condition: $a at 0 }
"""
    text = apkid_rules_to_bundle_toml(yara, fetched="2026-06-09")
    assert "[[rule]]" not in text


def test_regex_string_and_nocase(tmp_path) -> None:
    yara = """
// dumpa-apkid-source: obfuscators/r.yara
rule r
{
    meta:
        description = "regex obf"
    strings:
        $a = /assets\\/proguard\\/.*\\.txt/ nocase
    condition:
        any of them
}
"""
    bundle, _ = _load(yara, tmp_path)
    r = next(r for r in bundle.rules if r.subject == "regex obf")
    assert r.regex and r.case_insensitive is True
    assert r.attributes["category"] == "obfuscator"


def test_subject_falls_back_to_humanized_rule_name(tmp_path) -> None:
    yara = """
// dumpa-apkid-source: packers/p.yara
rule some_packer_v2 { strings: $a = "libsomepack.so" condition: any of them }
"""
    bundle, _ = _load(yara, tmp_path)
    assert any(r.subject == "some packer v2" for r in bundle.rules)


def test_version_is_deterministic_for_same_data(tmp_path) -> None:
    a = apkid_rules_to_bundle_toml(_JIAGU, fetched="2026-06-09")
    b = apkid_rules_to_bundle_toml(_JIAGU, fetched="2030-01-01")
    va = next(line for line in a.splitlines() if line.startswith("version"))
    vb = next(line for line in b.splitlines() if line.startswith("version"))
    assert va == vb and "apkid.1." in va         # one subject, content-keyed version


def test_provenance_recorded(tmp_path) -> None:
    bundle, _ = _load(_JIAGU, tmp_path)
    assert bundle.name == "protections-apkid"
    assert "APKiD" in bundle.source
    assert "GPL-3.0" in bundle.license
    assert bundle.updated == "2026-06-09"


def test_vendored_seed_parses(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty"))
    from dumpa.core.rules import load_builtin
    bundle = load_builtin("protections_apkid")
    assert bundle.name == "protections-apkid"
    assert bundle.rules                          # the committed snapshot is non-empty
    assert all(r.kind == "protection" for r in bundle.rules)
