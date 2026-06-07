"""Manifest privacy-audit scanner: structural risk signals + permission combos."""

from __future__ import annotations

from pathlib import Path

from _axml_build import build_axml

from dumpa.core.workspace import Workspace
from dumpa.scanners import manifest_privacy


def _ws(tmp_path: Path, tree: tuple) -> Workspace:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    (extracted / "AndroidManifest.xml").write_bytes(build_axml(tree))
    return Workspace(root=tmp_path)


def test_exported_debuggable_boot_and_deeplink(tmp_path: Path) -> None:
    tree = ("manifest", {"package": "com.example.game"}, [
        ("uses-permission", {"name": "android.permission.ACCESS_FINE_LOCATION"}, []),
        ("uses-permission", {"name": "android.permission.INTERNET"}, []),
        ("application", {"debuggable": True, "allowBackup": True}, [
            ("activity", {"name": ".Main", "exported": True}, [
                ("intent-filter", {}, [
                    ("action", {"name": "android.intent.action.VIEW"}, []),
                    ("category", {"name": "android.intent.category.BROWSABLE"}, []),
                    ("data", {"scheme": "https", "host": "go.example.com"}, []),
                ]),
            ]),
            ("receiver", {"name": ".Boot", "exported": False}, [
                ("intent-filter", {}, [
                    ("action", {"name": "android.intent.action.BOOT_COMPLETED"}, []),
                ]),
            ]),
        ]),
    ])
    findings = manifest_privacy.scan(_ws(tmp_path, tree))
    subjects = {f.subject for f in findings}

    assert "exported activity: .Main" in subjects
    assert "debuggable=true" in subjects
    assert "allowBackup=true" in subjects
    assert "boot receiver: .Boot" in subjects
    assert "deep link: https://go.example.com" in subjects
    # permission-combo bundle fires for location + internet
    assert "Precise location + network egress" in subjects

    exported = next(f for f in findings if f.subject == "exported activity: .Main")
    assert exported.attributes["guarded"] == "no"
    assert exported.locations[0].manifest_entry == ".Main"


def test_clean_manifest_minimal_findings(tmp_path: Path) -> None:
    tree = ("manifest", {"package": "com.example.clean"}, [
        ("application", {"allowBackup": False}, [
            ("activity", {"name": ".Main"}, []),       # not exported, no filter
        ]),
    ])
    findings = manifest_privacy.scan(_ws(tmp_path, tree))
    assert findings == []


def test_no_manifest_returns_empty(tmp_path: Path) -> None:
    (tmp_path / "extracted").mkdir()
    assert manifest_privacy.scan(Workspace(root=tmp_path)) == []
