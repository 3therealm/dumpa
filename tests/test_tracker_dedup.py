"""Tracker scanner: curated/Exodus coexistence — class-path dedup, loader override, floor.

`_dedup_exodus` drops imported subjects the curated bundle already covers; the user-dir
override lets `dumpa update-signatures` shadow the vendored snapshot; and the vendored
floor actually fires on an Exodus-only signature.
"""

from __future__ import annotations

from pathlib import Path


def _bundle(rules_toml: str, tmp_path: Path, name: str = "b"):
    from dumpa.core.rules import load_bundle
    p = tmp_path / f"{name}.toml"
    p.write_text(f'[bundle]\nname="{name}"\nversion="1"\nupdated="d"\n\n{rules_toml}')
    return load_bundle(p)


def test_dedup_drops_covered_subject(tmp_path: Path) -> None:
    from dumpa.scanners.tracker import _dedup_exodus
    curated = _bundle(
        '[[rule]]\nkind="tracker"\nsubject="Firebase"\nconfidence="high"\n'
        'strings=["com/google/firebase/analytics"]\n', tmp_path, "curated")
    exodus = _bundle(
        '[[rule]]\nkind="tracker"\nsubject="Firebase Analytics"\nconfidence="medium"\n'
        'regex=["com.google.firebase.analytics"]\n\n'
        '[[rule]]\nkind="tracker"\nsubject="Branch"\nconfidence="medium"\n'
        'regex=["io.branch.referral"]\n', tmp_path, "exodus")
    kept = _dedup_exodus(exodus, curated)               # type: ignore[arg-type]
    assert {r.subject for r in kept.rules} == {"Branch"}   # Firebase Analytics dropped


def test_dedup_keeps_when_no_overlap(tmp_path: Path) -> None:
    from dumpa.scanners.tracker import _dedup_exodus
    curated = _bundle(
        '[[rule]]\nkind="tracker"\nsubject="Unity Ads"\nconfidence="high"\n'
        'strings=["com/unity3d/ads"]\n', tmp_path, "curated")
    exodus = _bundle(
        '[[rule]]\nkind="tracker"\nsubject="Branch"\nconfidence="medium"\n'
        'regex=["io.branch.referral"]\n', tmp_path, "exodus")
    kept = _dedup_exodus(exodus, curated)               # type: ignore[arg-type]
    assert {r.subject for r in kept.rules} == {"Branch"}


def test_user_override_preferred(tmp_path: Path, monkeypatch) -> None:
    from dumpa.core.rules import load_builtin
    user_dir = tmp_path / "dumpa" / "rules"
    user_dir.mkdir(parents=True)
    (user_dir / "trackers_exodus.toml").write_text(
        '[bundle]\nname="trackers-exodus"\nversion="user.1"\nupdated="d"\n\n'
        '[[rule]]\nkind="tracker"\nsubject="OnlyInUser"\nconfidence="medium"\n'
        'regex=["com.only.user"]\n')
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    bundle = load_builtin("trackers_exodus")
    assert bundle.version == "user.1"
    assert {r.subject for r in bundle.rules} == {"OnlyInUser"}


def test_vendored_floor_fires_on_exodus_only_signature(tmp_path: Path, monkeypatch) -> None:
    # Keep the override out of the way so the in-repo vendored snapshot is what loads.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty"))
    from dumpa.core.workspace import Workspace
    from dumpa.scanners.tracker import scan
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    # Kochava is in the vendored seed and not in the curated bundle.
    (ws.extracted_dir / "classes.dex").write_bytes(b"junk Lcom/kochava/base/Tracker; junk")
    findings = scan(ws)
    kochava = [f for f in findings if f.subject == "Kochava"]
    assert len(kochava) == 1
    assert kochava[0].confidence.value == "medium"
