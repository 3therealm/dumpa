"""Regex content matcher + secrets bundle/scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.core.errors import ConfigError
from dumpa.core.rules import apply_bundle, load_builtin, load_bundle
from dumpa.core.workspace import Workspace
from dumpa.scanners import secret as secret_scanner


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "bundle.toml"
    p.write_text(text)
    return p


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


_REGEX_BUNDLE = """\
[bundle]
name = "t"
version = "1"
updated = "2026-01-01"

[[rule]]
kind = "secret"
subject = "Google API key"
confidence = "high"
category = "api-key"
regex = ['AIza[0-9A-Za-z_\\-]{35}']
"""


def test_regex_rule_captures_match(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _REGEX_BUNDLE))
    key = "AIza" + "B" * 35
    ex = tmp_path / "ex"
    (ex).mkdir()
    (ex / "classes.dex").write_bytes(b'const-string v0, "' + key.encode() + b'"')
    findings = apply_bundle(bundle, ex)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "secret"
    assert f.attributes["category"] == "api-key"
    assert f.evidence[0].snippet == key          # captured value surfaced
    assert f.locations[0].file_offset is not None


def test_regex_no_false_positive(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _REGEX_BUNDLE))
    ex = tmp_path / "ex"
    ex.mkdir()
    (ex / "classes.dex").write_bytes(b"AIzaTOOSHORT")
    assert apply_bundle(bundle, ex) == []


def test_invalid_regex_raises(tmp_path: Path) -> None:
    text = ('[bundle]\nname="t"\nversion="1"\nupdated="d"\n\n'
            "[[rule]]\nkind=\"secret\"\nsubject=\"X\"\nconfidence=\"high\"\nregex=['(unclosed']\n")
    with pytest.raises(ConfigError, match="invalid regex"):
        load_bundle(_write(tmp_path, text))


def test_three_way_matcher_exclusivity(tmp_path: Path) -> None:
    text = ('[bundle]\nname="t"\nversion="1"\nupdated="d"\n\n'
            '[[rule]]\nkind="secret"\nsubject="X"\nconfidence="high"\nstrings=["a"]\nregex=["b"]\n')
    with pytest.raises(ConfigError, match="exactly one"):
        load_bundle(_write(tmp_path, text))


def test_secrets_bundle_loads() -> None:
    bundle = load_builtin("secrets")
    assert bundle.name == "secrets"
    assert all(bool(r.regex) for r in bundle.rules)


def test_secret_scanner_finds_aws_key(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "classes.dex").write_bytes(b"creds AKIA" + b"A" * 16 + b" end")
    findings = secret_scanner.scan(ws)
    assert any(f.subject == "AWS access key ID" for f in findings)


def test_secret_scanner_clean(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "classes.dex").write_bytes(b"no secrets present")
    assert secret_scanner.scan(ws) == []
