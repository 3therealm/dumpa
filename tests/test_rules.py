"""Rule bundle loading + the path-glob matching engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.core.errors import ConfigError
from dumpa.core.report import Confidence, FindingState
from dumpa.core.rules import (
    apply_bundle,
    builtin_bundle_names,
    load_builtin,
    load_bundle,
)


def _touch(root: Path, rel: str, data: bytes = b"\x00") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


# --- built-in engines bundle -------------------------------------------------

def test_engines_is_a_builtin() -> None:
    assert "engines" in builtin_bundle_names()


def test_load_builtin_engines_provenance() -> None:
    bundle = load_builtin("engines")
    assert bundle.name == "engines"
    assert bundle.version
    assert bundle.source == "dumpa built-in"  # explicit in the TOML wins over the default
    assert len(bundle.rules) >= 10


def test_load_builtin_unknown_raises() -> None:
    with pytest.raises(ConfigError, match="no built-in rule bundle"):
        load_builtin("does-not-exist")


# --- matching ----------------------------------------------------------------

def test_apply_detects_unity_and_flutter(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    _touch(extracted, "lib/arm64-v8a/libil2cpp.so")
    _touch(extracted, "assets/flutter_assets/kernel_blob.bin")
    findings = apply_bundle(load_builtin("engines"), extracted)
    subjects = {f.subject for f in findings}
    assert "Unity" in subjects
    assert "Flutter" in subjects
    unity = next(f for f in findings if f.subject == "Unity")
    assert unity.kind == "engine"
    assert unity.confidence is Confidence.HIGH
    assert unity.state is FindingState.PRESENT
    assert unity.evidence and unity.evidence[0].snippet == "lib/arm64-v8a/libil2cpp.so"
    assert unity.locations[0].file_path == "lib/arm64-v8a/libil2cpp.so"


def test_apply_no_match_is_empty(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    _touch(extracted, "AndroidManifest.xml")
    assert apply_bundle(load_builtin("engines"), extracted) == []


# --- custom bundles + match modes -------------------------------------------

_ALL_BUNDLE = """\
[bundle]
name = "t"
version = "1"
updated = "2026-01-01"

[[rule]]
kind = "engine"
subject = "Both"
confidence = "high"
match = "all"
globs = ["a.txt", "b.txt"]
"""


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "bundle.toml"
    p.write_text(text)
    return p


def test_match_all_requires_every_glob(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _ALL_BUNDLE))
    extracted = tmp_path / "ex"
    _touch(extracted, "a.txt")
    assert apply_bundle(bundle, extracted) == []          # only one of two globs
    _touch(extracted, "b.txt")
    assert len(apply_bundle(bundle, extracted)) == 1      # both now present


def test_custom_bundle_default_source_is_path(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _ALL_BUNDLE))
    assert bundle.source == str(tmp_path / "bundle.toml")


def test_missing_globs_raises(tmp_path: Path) -> None:
    text = '[bundle]\nname="x"\nversion="1"\nupdated="d"\n\n[[rule]]\nkind="engine"\nsubject="X"\nconfidence="high"\n'
    with pytest.raises(ConfigError, match="globs"):
        load_bundle(_write(tmp_path, text))


def test_bad_confidence_raises(tmp_path: Path) -> None:
    text = ('[bundle]\nname="x"\nversion="1"\nupdated="d"\n\n'
            '[[rule]]\nkind="engine"\nsubject="X"\nconfidence="sometimes"\nglobs=["a"]\n')
    with pytest.raises(ConfigError, match="confidence"):
        load_bundle(_write(tmp_path, text))


def test_parent_directory_glob_raises(tmp_path: Path) -> None:
    text = ('[bundle]\nname="x"\nversion="1"\nupdated="d"\n\n'
            '[[rule]]\nkind="engine"\nsubject="X"\nconfidence="high"\nglobs=["../outside.txt"]\n')
    with pytest.raises(ConfigError, match="unsafe glob"):
        load_bundle(_write(tmp_path, text))


# --- content (string) matchers ----------------------------------------------

_CONTENT_BUNDLE = """\
[bundle]
name = "t"
version = "1"
updated = "2026-01-01"

[[rule]]
kind = "tracker"
subject = "Firebase"
confidence = "high"
category = "analytics"
owner = "Google"
strings = ["com/google/firebase/analytics"]
"""


def test_content_rule_detects_string(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _CONTENT_BUNDLE))
    ex = tmp_path / "ex"
    _touch(ex, "classes.dex", b"xx Lcom/google/firebase/analytics; yy")
    findings = apply_bundle(bundle, ex)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "tracker"
    assert f.subject == "Firebase"
    assert f.attributes == {"category": "analytics", "owner": "Google"}
    assert f.locations[0].file_path == "classes.dex"
    assert f.locations[0].file_offset is not None


def test_content_rule_no_match(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _CONTENT_BUNDLE))
    ex = tmp_path / "ex"
    _touch(ex, "classes.dex", b"nothing interesting here")
    assert apply_bundle(bundle, ex) == []


def test_content_match_spans_chunk_boundary(tmp_path: Path) -> None:
    text = ('[bundle]\nname="t"\nversion="1"\nupdated="d"\n\n'
            '[[rule]]\nkind="tracker"\nsubject="X"\nconfidence="high"\nstrings=["com/example/sdk"]\n')
    bundle = load_bundle(_write(tmp_path, text))
    ex = tmp_path / "ex"
    pad = b"\x00" * ((1 << 20) - 5)          # needle straddles the 1 MiB chunk edge
    _touch(ex, "classes.dex", pad + b"com/example/sdk" + b"\x00" * 10)
    findings = apply_bundle(bundle, ex)
    assert len(findings) == 1
    assert findings[0].locations[0].file_offset == len(pad)


def test_content_match_all(tmp_path: Path) -> None:
    text = ('[bundle]\nname="t"\nversion="1"\nupdated="d"\n\n'
            '[[rule]]\nkind="tracker"\nsubject="X"\nconfidence="high"\nmatch="all"\n'
            'strings=["aaa", "bbb"]\n')
    bundle = load_bundle(_write(tmp_path, text))
    ex = tmp_path / "ex"
    _touch(ex, "classes.dex", b"only aaa here")
    assert apply_bundle(bundle, ex) == []
    _touch(ex, "classes.dex", b"aaa and bbb here")
    assert len(apply_bundle(bundle, ex)) == 1


def test_rule_requires_exactly_one_matcher(tmp_path: Path) -> None:
    both = ('[bundle]\nname="t"\nversion="1"\nupdated="d"\n\n'
            '[[rule]]\nkind="tracker"\nsubject="X"\nconfidence="high"\nglobs=["a"]\nstrings=["b"]\n')
    with pytest.raises(ConfigError, match="exactly one"):
        load_bundle(_write(tmp_path, both))
    neither = '[bundle]\nname="t"\nversion="1"\nupdated="d"\n\n[[rule]]\nkind="t"\nsubject="X"\nconfidence="high"\n'
    with pytest.raises(ConfigError, match="exactly one"):
        load_bundle(_write(tmp_path, neither))


def test_content_strings_must_be_non_empty_strings(tmp_path: Path) -> None:
    text = ('[bundle]\nname="t"\nversion="1"\nupdated="d"\n\n'
            '[[rule]]\nkind="tracker"\nsubject="X"\nconfidence="high"\nstrings=["ok", 3]\n')
    with pytest.raises(ConfigError, match="strings"):
        load_bundle(_write(tmp_path, text))


def test_trackers_builtin_loads() -> None:
    bundle = load_builtin("trackers")
    assert bundle.name == "trackers"
    assert len(bundle.rules) >= 20
    assert all(r.is_content for r in bundle.rules)


def test_missing_bundle_table_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"\[bundle\]"):
        load_bundle(_write(tmp_path, '[[rule]]\nkind="e"\nsubject="X"\nconfidence="high"\nglobs=["a"]\n'))
