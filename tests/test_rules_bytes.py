"""The `hex` byte-pattern matcher: lowering, parsing/validation, and matching."""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.core.errors import ConfigError
from dumpa.core.rules import apply_bundle, compile_hex, load_bundle


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "bundle.toml"
    p.write_text(text)
    return p


def _touch(root: Path, rel: str, data: bytes) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _hex_bundle(patterns: str, *, match: str = "any", extra: str = "") -> str:
    return ('[bundle]\nname="t"\nversion="1"\nupdated="d"\n\n'
            '[[rule]]\nkind="protection"\nsubject="X"\nconfidence="high"\n'
            f'category="packer"\nhex={patterns}\nmatch="{match}"\n{extra}')


# --- compile_hex (lowering) --------------------------------------------------

def test_compile_hex_lowers_and_anchors() -> None:
    compiled, anchors = compile_hex("DE AD BE EF ??")
    assert anchors == [b"\xde\xad\xbe\xef"]               # longest fixed run
    assert compiled.search(b"\x00\xde\xad\xbe\xef\x99") is not None


def test_compile_hex_spaces_optional() -> None:
    spaced, _ = compile_hex("48 8B ?? E8")
    compact, _ = compile_hex("488B??E8")
    assert spaced.pattern == compact.pattern


def test_compile_hex_short_run_has_no_anchor() -> None:
    # longest fixed run is 1 byte (< const_min_byte_anchor) -> always-run fallback
    _, anchors = compile_hex("AB ?? CD")
    assert anchors is None


def test_compile_hex_wildcard_matches_newline_byte() -> None:
    # re.DOTALL: '??' must match 0x0A, which a bare '.' would not
    compiled, _ = compile_hex("41 ?? 42")
    assert compiled.search(b"A\x0aB") is not None


@pytest.mark.parametrize("bad", ["", "ABC", "ZZ", "????", "??"])
def test_compile_hex_rejects_bad_patterns(bad: str) -> None:
    with pytest.raises(ConfigError):
        compile_hex(bad)


def test_compile_hex_rejects_over_long() -> None:
    with pytest.raises(ConfigError, match="exceeds"):
        compile_hex("00" * 1025)


# --- parsing / validation ----------------------------------------------------

def test_hex_rule_loads(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _hex_bundle('["DE AD BE EF"]')))
    rule = bundle.rules[0]
    assert rule.bytes_hex == ("DE AD BE EF",)
    assert rule.is_content
    assert rule.keys == ("DE AD BE EF",)


def test_hex_with_other_matcher_rejected(tmp_path: Path) -> None:
    text = _hex_bundle('["DEAD"]', extra='strings=["x"]\n')
    with pytest.raises(ConfigError, match="exactly one"):
        load_bundle(_write(tmp_path, text))


def test_hex_all_wildcard_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="fixed byte"):
        load_bundle(_write(tmp_path, _hex_bundle('["?? ??"]')))


def test_hex_case_insensitive_rejected(tmp_path: Path) -> None:
    text = _hex_bundle('["DEAD"]', extra="case_insensitive=true\n")
    with pytest.raises(ConfigError, match="meaningless"):
        load_bundle(_write(tmp_path, text))


# --- matching ----------------------------------------------------------------

def test_hex_matches_in_dex(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _hex_bundle('["DE AD BE EF"]')))
    ex = tmp_path / "ex"
    _touch(ex, "classes.dex", b"junk\xde\xad\xbe\xeftail")
    findings = apply_bundle(bundle, ex)
    assert len(findings) == 1
    loc = findings[0].locations[0]
    assert loc.file_path == "classes.dex"
    assert loc.file_offset == 4


def test_hex_wildcard_matches_any_byte_including_newline(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _hex_bundle('["41 ?? ?? 42"]')))
    ex = tmp_path / "ex"
    _touch(ex, "classes.dex", b"A\x0a\xff" + b"B")
    assert len(apply_bundle(bundle, ex)) == 1


def test_hex_no_match(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _hex_bundle('["DE AD BE EF"]')))
    ex = tmp_path / "ex"
    _touch(ex, "classes.dex", b"nothing to see here")
    assert apply_bundle(bundle, ex) == []


def test_hex_short_run_still_matches(tmp_path: Path) -> None:
    # anchor is None (run < 4); the always-run path must still find it
    bundle = load_bundle(_write(tmp_path, _hex_bundle('["AB ?? CD"]')))
    ex = tmp_path / "ex"
    _touch(ex, "classes.dex", b"\xab\x99\xcd")
    assert len(apply_bundle(bundle, ex)) == 1


def test_hex_match_all(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _hex_bundle('["DEAD", "BEEF"]', match="all")))
    ex = tmp_path / "ex"
    _touch(ex, "classes.dex", b"\xde\xad only")
    assert apply_bundle(bundle, ex) == []                 # only one of two present
    _touch(ex, "classes.dex", b"\xde\xad and \xbe\xef")
    assert len(apply_bundle(bundle, ex)) == 1


def test_hex_match_spans_chunk_boundary(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _hex_bundle('["DE AD BE EF"]')))
    ex = tmp_path / "ex"
    pad = b"\x00" * ((1 << 20) - 2)                       # sig straddles the 1 MiB edge
    _touch(ex, "classes.dex", pad + b"\xde\xad\xbe\xef" + b"\x00" * 10)
    findings = apply_bundle(bundle, ex)
    assert len(findings) == 1
    assert findings[0].locations[0].file_offset == len(pad)


def test_hex_evidence_rendered_as_hex(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _hex_bundle('["DE AD BE EF"]')))
    ex = tmp_path / "ex"
    _touch(ex, "classes.dex", b"x\xde\xad\xbe\xefy")
    ev = apply_bundle(bundle, ex)[0].evidence[0]
    assert ev.snippet == "de ad be ef"
    assert "byte pattern" in ev.description
