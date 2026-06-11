"""Unity deep-helper scanners (unity_rules, unity_assets) and the Unity gate in run_all."""

from __future__ import annotations

from pathlib import Path

from dumpa.core.report import FindingState
from dumpa.core.workspace import Workspace
from dumpa.scanners import UNITY_SPECS, run_all
from dumpa.scanners import unity_assets as assets_scanner
from dumpa.scanners import unity_rules as rules_scanner


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


def _touch(root: Path, rel: str, data: bytes = b"\x00") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


# --- unity_rules -------------------------------------------------------------

def test_unity_rules_detects_service_in_dex(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "classes.dex", b"junk Lcom/unity3d/services/analytics/Foo; junk")
    subjects = {f.subject for f in rules_scanner.scan(ws)}
    assert "Unity service: Analytics" in subjects


def test_unity_rules_detects_firebase_config_residue(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "resources.arsc", b"\x00 google_app_id \x00 gcm_defaultSenderId")
    findings = rules_scanner.scan(ws)
    f = next(f for f in findings if f.subject.startswith("Firebase config"))
    assert f.state == FindingState.PRESENT


def test_unity_rules_detects_firebase_native_lib(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libFirebaseCppApp.so")
    assert any(f.subject.startswith("Firebase native runtime") for f in rules_scanner.scan(ws))


def test_unity_rules_detects_addressables_catalog(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "assets/aa/catalog.json", b"{}")
    assert any(f.subject == "Unity Addressables catalog" for f in rules_scanner.scan(ws))


def test_unity_rules_detects_play_games_plugin(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/armeabi-v7a/libgpg.so")
    assert any("Google Play Games" in f.subject for f in rules_scanner.scan(ws))


def test_unity_rules_empty_on_bare_tree(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "classes.dex", b"nothing unity here")
    assert rules_scanner.scan(ws) == []


# --- unity_assets (Addressables remote URL attribution) ----------------------

def test_unity_assets_attributes_remote_host(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    catalog = b'{"m_InternalIds":["https://cdn.example.com/aa/bundle_a.bundle","local/path"]}'
    _touch(ws.extracted_dir, "assets/aa/catalog.json", catalog)
    findings = assets_scanner.scan(ws)
    assert [f.subject for f in findings] == ["Addressables remote content: cdn.example.com"]
    assert findings[0].state == FindingState.REFERENCED
    assert findings[0].locations[0].domain == "cdn.example.com"


def test_unity_assets_no_remote_ids(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "assets/aa/catalog.json", b'{"m_InternalIds":["local/only.bundle"]}')
    assert assets_scanner.scan(ws) == []


def test_unity_assets_no_catalog(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "assets/other.json", b"https://cdn.example.com/x")
    assert assets_scanner.scan(ws) == []


# --- gate integrity (run_all) ------------------------------------------------

def test_unity_specs_run_only_for_unity(tmp_path: Path) -> None:
    """A non-Unity tree must not surface any Unity-spec findings even if markers exist."""
    ws = _ws(tmp_path)
    # Addressables-looking file + a service string, but NO Unity engine marker.
    _touch(ws.extracted_dir, "assets/aa/catalog.json",
           b'{"m_InternalIds":["https://cdn.example.com/x"]}')
    _touch(ws.extracted_dir, "classes.dex", b"Lcom/unity3d/services/analytics/Foo;")
    unity_spec_names = {s.name for s in UNITY_SPECS}
    findings = run_all(ws, use_cache=False)
    assert not any(f.kind == "engine-detail" for f in findings)
    assert not any(f.subject.startswith("Addressables remote") for f in findings)
    # sanity: the gate keys on an engine/Unity finding, which is absent here
    assert not any(f.kind == "engine" and f.subject == "Unity" for f in findings)
    assert unity_spec_names == {"unity", "unity_rules", "unity_assets"}


def test_unity_specs_run_when_unity_detected(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")          # engine -> Unity
    _touch(ws.extracted_dir, "classes.dex", b"Lcom/unity3d/services/analytics/Foo;")
    _touch(ws.extracted_dir, "assets/aa/catalog.json",
           b'{"m_InternalIds":["https://cdn.example.com/x"]}')
    findings = run_all(ws, use_cache=False)
    subjects = {f.subject for f in findings}
    assert "Unity service: Analytics" in subjects
    assert any(s.startswith("Addressables remote content") for s in subjects)
