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


def _touch(root: Path, rel: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\x00")


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


def test_missing_bundle_table_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"\[bundle\]"):
        load_bundle(_write(tmp_path, '[[rule]]\nkind="e"\nsubject="X"\nconfidence="high"\nglobs=["a"]\n'))
