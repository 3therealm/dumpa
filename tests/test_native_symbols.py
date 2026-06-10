"""Native-symbol matcher: parser, `match_symbol_rules`, and the scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dumpa.core.errors import ConfigError
from dumpa.core.report import Confidence
from dumpa.core.rules import (
    NativeSymbols,
    Rule,
    RuleBundle,
    load_bundle,
    match_symbol_rules,
)
from dumpa.core.workspace import Workspace
from dumpa.scanners import native_symbols as ns

_BUNDLE = """
[bundle]
name = "t"
version = "1"
updated = "2026-06-10"

[[rule]]
kind = "protection"
subject = "ptrace import"
confidence = "medium"
symbols = ['^ptrace$']
symbol_scope = "imports"

[[rule]]
kind = "native-symbol-marker"
subject = "JNI_OnLoad export"
confidence = "low"
symbols = ['^JNI_OnLoad$']
symbol_scope = "exports"
"""


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "b.toml"
    p.write_text(text, encoding="UTF-8")
    return p


def _lib() -> NativeSymbols:
    return NativeSymbols(
        rel_path="lib/arm64-v8a/libfoo.so", abi="arm64-v8a",
        exports=(("JNI_OnLoad", 4096), ("bar", 8192)),
        imports=("ptrace", "malloc"),
    )


# --- parser ------------------------------------------------------------------

def test_symbols_rule_parses(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _BUNDLE))
    rule = bundle.rules[0]
    assert rule.is_symbol
    assert rule.symbols == ("^ptrace$",)
    assert rule.symbol_scope == "imports"


def test_symbols_combined_with_another_kind_raises(tmp_path: Path) -> None:
    text = _BUNDLE + "globs = ['lib/*/x.so']\n"
    with pytest.raises(ConfigError, match="exactly one"):
        load_bundle(_write(tmp_path, text))


def test_bad_symbol_scope_raises(tmp_path: Path) -> None:
    text = """
[bundle]
name = "t"
version = "1"
updated = "2026-06-10"

[[rule]]
kind = "protection"
subject = "x"
confidence = "low"
symbols = ['y']
symbol_scope = "bogus"
"""
    with pytest.raises(ConfigError, match="symbol_scope"):
        load_bundle(_write(tmp_path, text))


def test_symbol_scope_without_symbols_raises(tmp_path: Path) -> None:
    text = """
[bundle]
name = "t"
version = "1"
updated = "2026-06-10"

[[rule]]
kind = "engine"
subject = "x"
confidence = "low"
globs = ['lib/*/x.so']
symbol_scope = "exports"
"""
    with pytest.raises(ConfigError, match="symbol_scope"):
        load_bundle(_write(tmp_path, text))


# --- match_symbol_rules ------------------------------------------------------

def test_export_match_carries_rva(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _BUNDLE))
    rule = next(r for r in bundle.rules if r.subject == "JNI_OnLoad export")
    [finding] = match_symbol_rules([rule], bundle, [_lib()])
    assert finding.subject == "JNI_OnLoad export"
    assert [loc.rva for loc in finding.locations] == [4096]
    assert finding.evidence[0].snippet == "JNI_OnLoad"
    assert finding.evidence[0].tool == "native-symbol"


def test_import_scope_excludes_exports(tmp_path: Path) -> None:
    # ptrace is an import -> fires; would not fire if scoped to exports.
    bundle = load_bundle(_write(tmp_path, _BUNDLE))
    rule = next(r for r in bundle.rules if r.subject == "ptrace import")
    [finding] = match_symbol_rules([rule], bundle, [_lib()])
    assert finding.locations[0].rva is None        # imports have no RVA


def test_match_all_requires_every_pattern() -> None:
    bundle = RuleBundle(name="t", version="1", source="x", updated="2026-06-10", rules=())
    rule_all = Rule(
        kind="protection", subject="both", confidence=Confidence.HIGH,
        symbols=("^JNI_OnLoad$", "^absent$"), symbol_scope="any", match="all",
    )
    assert match_symbol_rules([rule_all], bundle, [_lib()]) == []
    rule_any = Rule(
        kind="protection", subject="either", confidence=Confidence.HIGH,
        symbols=("^JNI_OnLoad$", "^absent$"), symbol_scope="any", match="any",
    )
    assert len(match_symbol_rules([rule_any], bundle, [_lib()])) == 1


def test_no_false_fire() -> None:
    bundle = RuleBundle(name="t", version="1", source="x", updated="2026-06-10", rules=())
    rule = Rule(kind="protection", subject="nope", confidence=Confidence.LOW,
                symbols=("^does_not_exist$",), symbol_scope="any")
    assert match_symbol_rules([rule], bundle, [_lib()]) == []


# --- scanner -----------------------------------------------------------------

def test_scanner_reads_sidecar(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    (ws.extracted_dir / "lib" / "arm64-v8a").mkdir(parents=True)
    # A real (if tiny) .so so the scanner's glob picks the lib up; the sidecar supplies symbols.
    (ws.extracted_dir / "lib" / "arm64-v8a" / "libfoo.so").write_bytes(b"\x7fELF")
    ws.native_dir.mkdir(parents=True)
    (ws.native_dir / "arm64-v8a__libfoo.so.json").write_text(json.dumps({
        "abi": "arm64-v8a", "lib": "libfoo.so",
        "exports": [{"name": "JNI_OnLoad", "rva": 4096, "size": 8}],
        "imports": [{"name": "ptrace"}],
    }), encoding="UTF-8")

    findings = ns.scan(ws)
    subjects = {f.subject for f in findings}
    assert "JNI_OnLoad entry point" in subjects
    assert "ptrace anti-debug (native import)" in subjects
    jni = next(f for f in findings if f.subject == "JNI_OnLoad entry point")
    assert jni.locations[0].rva == 4096
