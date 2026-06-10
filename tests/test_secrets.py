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


_SLACK_BUNDLE = """\
[bundle]
name = "t"
version = "1"
updated = "2026-01-01"

[[rule]]
kind = "secret"
subject = "Slack token"
confidence = "high"
regex = ['xox[baprs]-[0-9A-Za-z-]{10,}']
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


def test_regex_rule_captures_match_across_chunk_boundary(tmp_path: Path) -> None:
    bundle = load_bundle(_write(tmp_path, _SLACK_BUNDLE))
    token = "xoxb-" + "A" * 80
    ex = tmp_path / "ex"
    ex.mkdir()
    prefix = b"\x00" * ((1 << 20) - 15)
    (ex / "classes.dex").write_bytes(prefix + token.encode() + b" ")

    findings = apply_bundle(bundle, ex)

    assert len(findings) == 1
    f = findings[0]
    assert f.evidence[0].snippet == token
    assert f.locations[0].file_offset == len(prefix)


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


@pytest.mark.parametrize(
    ("value", "subject", "category"),
    [
        (b"UA-123456-1", "Google Universal Analytics ID", "analytics-id"),
        (b"G-ABC1234567", "Google Analytics 4 measurement ID", "analytics-id"),
        (b"GTM-ABCD12", "Google Tag Manager ID", "analytics-id"),
        (b"1:1234567890:android:abcdef0123456789",
         "Firebase / Google mobile app ID", "analytics-id"),
        (b"ca-app-pub-3940256099942544~3347511713",
         "AdMob application ID", "ad-network-id"),
        (b"ca-app-pub-3940256099942544/1033173712",
         "AdMob ad-unit ID", "ad-network-id"),
    ],
)
def test_secret_scanner_finds_id(
    tmp_path: Path, value: bytes, subject: str, category: str
) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "classes.dex").write_bytes(b'id "' + value + b'" end')
    findings = secret_scanner.scan(ws)
    f = next(f for f in findings if f.subject == subject)
    assert f.attributes["category"] == category
    assert f.evidence[0].snippet == value.decode()


@pytest.mark.parametrize(
    "value",
    [b"ca-app-pub-123/4", b"UA--", b"GTM-AB", b"1:12:ios:abcdef01"],
)
def test_secret_scanner_id_no_false_positive(tmp_path: Path, value: bytes) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "classes.dex").write_bytes(b"x " + value + b" x")
    subjects = {f.subject for f in secret_scanner.scan(ws)}
    assert subjects.isdisjoint({
        "Google Universal Analytics ID", "Google Tag Manager ID",
        "Firebase / Google mobile app ID", "AdMob application ID", "AdMob ad-unit ID",
    })
