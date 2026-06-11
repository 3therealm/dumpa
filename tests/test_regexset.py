"""_RegexSet: the combined-alternation regex matcher behind many-rule content scans.

Covers the fast combined path, the named-group/backref standalone fallback, per-source
case sensitivity, window-edge deferral vs at_eof, and parity with the naive per-pattern
result through apply_bundle (including a regex match that straddles the 1 MiB chunk edge).
"""

from __future__ import annotations

from pathlib import Path

from dumpa.core.rules import _RegexSet, apply_bundle, load_bundle


def _scan_once(sources: list[tuple[str, bool]], window: bytes, *, at_eof: bool = False) -> dict[str, str]:
    rs = _RegexSet(sources)
    return {src: m.group().decode() for src, m in rs.scan(window, at_eof=at_eof)}


def test_combined_matches_multiple_sources() -> None:
    hits = _scan_once([("com.adjust.sdk", False), ("io.branch.referral", False)],
                      b"xx com/adjust/sdk yy io/branch/referral zz")
    assert set(hits) == {"com.adjust.sdk", "io.branch.referral"}


def test_only_pending_sources_returned() -> None:
    rs = _RegexSet([("aaa", False), ("bbb", False)])
    assert {s for s, _ in rs.scan(b"-aaa-")} == {"aaa"}
    rs.discard("aaa")
    assert rs.pending == {"bbb"}
    assert {s for s, _ in rs.scan(b"-aaa-bbb-")} == {"bbb"}


def test_case_sensitivity_is_per_source() -> None:
    hits = _scan_once([("foo", True), ("bar", False)], b"FOO BAR")
    assert "foo" in hits          # case-insensitive source matches FOO
    assert "bar" not in hits      # case-sensitive source does not match BAR


def test_named_group_source_still_matches() -> None:
    # A source carrying its own named group is anchored on its literal run ("abc"/"def")
    # and must still match via the gated real regex.
    hits = _scan_once([("(?P<x>abc)def", False), ("plain", False)], b"abcdef plain end")
    assert set(hits) == {"(?P<x>abc)def", "plain"}


def test_unanchorable_source_runs_standalone() -> None:
    # No literal run >= const_min_anchor_len -> always-run standalone path, still matches.
    hits = _scan_once([(r"(a)\1", False)], b"zz aa zz")
    assert set(hits) == {r"(a)\1"}


def test_alternation_each_branch_anchored() -> None:
    # com.foo|com.bar -> one anchor per branch; a window matching only the second branch
    # must still fire (anchoring on just the first branch would miss it).
    src = [("doubleclick.net|googleadservices.com", False)]
    assert set(_scan_once(src, b"-- googleadservices/com --")) == {src[0][0]}
    assert set(_scan_once(src, b"-- doubleclick/net --")) == {src[0][0]}


def test_dotted_signature_matches_slash_form() -> None:
    # Exodus dots match the slash-form dex descriptors verbatim.
    hits = _scan_once([("com.kochava.base", False)], b"Lcom/kochava/base/Tracker;")
    assert set(hits) == {"com.kochava.base"}


def test_edge_match_deferred_unless_eof() -> None:
    window = b"....needle"          # match ends exactly at window end
    assert _scan_once([("needle", False)], window) == {}          # deferred
    assert _scan_once([("needle", False)], window, at_eof=True) == {"needle": "needle"}


_MANY = "\n".join(
    ['[bundle]', 'name="t"', 'version="1"', 'updated="d"', '']
    + [f'[[rule]]\nkind="tracker"\nsubject="s{i}"\nconfidence="medium"\nregex=["sig{i}xx"]\n'
       for i in range(300)]
)


def test_apply_bundle_many_regexes(tmp_path: Path) -> None:
    bundle = (tmp_path / "b.toml")
    bundle.write_text(_MANY)
    ex = tmp_path / "ex"
    ex.mkdir()
    (ex / "classes.dex").write_bytes(b"junk sig7xx junk sig250xx tail")
    findings = apply_bundle(load_bundle(bundle), ex)
    assert {f.subject for f in findings} == {"s7", "s250"}


def test_regex_spans_chunk_boundary(tmp_path: Path) -> None:
    text = ('[bundle]\nname="t"\nversion="1"\nupdated="d"\n\n'
            '[[rule]]\nkind="tracker"\nsubject="X"\nconfidence="medium"\nregex=["com/example/sdk"]\n')
    bundle = tmp_path / "b.toml"
    bundle.write_text(text)
    ex = tmp_path / "ex"
    ex.mkdir()
    pad = b"\x00" * ((1 << 20) - 5)          # needle straddles the 1 MiB chunk edge
    (ex / "classes.dex").write_bytes(pad + b"com/example/sdk" + b"\x00" * 10)
    findings = apply_bundle(load_bundle(bundle), ex)
    assert len(findings) == 1
    assert findings[0].locations[0].file_offset == len(pad)
