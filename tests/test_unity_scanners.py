"""Unity deep-helper scanners (unity_rules, unity_assets) and the Unity gate in run_all."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dumpa.core import unityasset
from dumpa.core.report import FindingState
from dumpa.core.unityasset import ExtractedString
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


# --- unity_assets (serialized-asset parsing via UnityPy adapter) -------------

def _es(text: str, *, name: str = "cfg", pid: int = 1, raw: bytes | None = None,
        cls: str = "TextAsset", container: str = "data.assets") -> ExtractedString:
    return ExtractedString(text=text, container=container, asset_name=name,
                           path_id=pid, class_name=cls, raw=raw)


def _seed_container(ws: Workspace) -> None:
    _touch(ws.extracted_dir, "data.assets", b"binary-serialized-bytes")


def test_unity_assets_skips_serialized_without_unitypy(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "assets/aa/catalog.json",
           b'{"m_InternalIds":["https://cdn.example.com/x"]}')
    _seed_container(ws)
    monkeypatch.setattr(unityasset, "available", lambda: False)
    findings = assets_scanner.scan(ws)
    assert any(f.subject.startswith("Addressables remote") for f in findings)  # half 1 still runs
    assert not any(f.kind == "endpoint" for f in findings)                     # half 2 skipped


def test_unity_assets_endpoint_from_textasset(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _ws(tmp_path)
    _seed_container(ws)
    body = b"server=https://api.example.com/v1"
    monkeypatch.setattr(unityasset, "available", lambda: True)
    monkeypatch.setattr(unityasset, "parse_container",
                        lambda path, rel, **kw: [_es(body.decode(), raw=body)])
    findings = assets_scanner.scan(ws)
    ep = [f for f in findings if f.kind == "endpoint"]
    assert ep and ep[0].subject == "api.example.com"
    assert ep[0].locations[0].file_path.startswith("dumps/unity/assets/")
    assert ep[0].attributes["unity_class"] == "TextAsset"
    on_disk = list((ws.dumps_dir / "unity" / "assets").iterdir())
    assert on_disk and on_disk[0].read_bytes() == body


def test_unity_assets_dump_names_include_container(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "a.assets")
    _touch(ws.extracted_dir, "b.assets")
    one = b"https://one.example.com"
    two = b"https://two.example.com"

    def fake_parse(_path: Path, rel: str, **_kw) -> list[ExtractedString]:
        raw = one if rel == "a.assets" else two
        return [_es(raw.decode(), name="cfg", pid=1, raw=raw, container=rel)]

    monkeypatch.setattr(unityasset, "available", lambda: True)
    monkeypatch.setattr(unityasset, "parse_container", fake_parse)

    findings = assets_scanner.scan(ws)

    dumps = sorted((ws.dumps_dir / "unity" / "assets").iterdir())
    assert len(dumps) == 2
    assert {p.read_bytes() for p in dumps} == {one, two}
    endpoints = {f.subject: f.locations[0].file_path for f in findings if f.kind == "endpoint"}
    assert endpoints["one.example.com"] != endpoints["two.example.com"]


def test_unity_assets_secret_from_dump(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _ws(tmp_path)
    _seed_container(ws)
    key = b"AIza" + b"B" * 35  # Google API key shape: AIza + 35 chars
    monkeypatch.setattr(unityasset, "available", lambda: True)
    monkeypatch.setattr(unityasset, "parse_container",
                        lambda path, rel, **kw: [_es(key.decode(), raw=key)])
    findings = assets_scanner.scan(ws)
    secrets = [f for f in findings if f.kind == "secret"]
    assert secrets
    assert secrets[0].locations[0].file_path.startswith("dumps/unity/assets/")


def test_unity_assets_dump_cap(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture) -> None:
    ws = _ws(tmp_path)
    _seed_container(ws)
    monkeypatch.setattr(unityasset, "available", lambda: True)
    monkeypatch.setattr(assets_scanner, "const_max_dump_files", 2)
    many = [_es(f"t{i}", name=f"a{i}", pid=i, raw=f"t{i}".encode()) for i in range(5)]
    monkeypatch.setattr(unityasset, "parse_container", lambda path, rel, **kw: many)
    with caplog.at_level("WARNING"):
        assets_scanner.scan(ws)
    on_disk = list((ws.dumps_dir / "unity" / "assets").iterdir())
    assert len(on_disk) == 2
    assert any("dump cap" in r.getMessage() for r in caplog.records)


def test_unity_assets_sidecar_written(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _ws(tmp_path)
    _seed_container(ws)
    monkeypatch.setattr(unityasset, "available", lambda: True)
    monkeypatch.setattr(unityasset, "parse_container",
                        lambda path, rel, **kw: [_es("hello", raw=b"hello")])
    assets_scanner.scan(ws)
    sidecar = ws.dumps_dir / "unity" / ".dumpa-unity-assets.json"
    assert sidecar.is_file()
    data = json.loads(sidecar.read_text())
    assert "unitypy_version" in data
    assert data["containers"] and data["dumped"]


def test_unity_assets_monobehaviour_string_no_dump(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """MonoBehaviour field strings are harvested but not dumped (raw is None)."""
    ws = _ws(tmp_path)
    _seed_container(ws)
    monkeypatch.setattr(unityasset, "available", lambda: True)
    monkeypatch.setattr(unityasset, "parse_container", lambda path, rel, **kw: [
        _es("https://mono.example.com/cfg", cls="MonoBehaviour", raw=None)])
    findings = assets_scanner.scan(ws)
    ep = [f for f in findings if f.kind == "endpoint"]
    assert ep and ep[0].subject == "mono.example.com"
    assert ep[0].locations[0].file_path == "data.assets"  # points at the container, not a dump
    assert not (ws.dumps_dir / "unity" / "assets").exists()


def test_unity_assets_endpoints_flow_through_run_all_gate(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Under the Unity gate, serialized-asset endpoints reach the assembled run_all output."""
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libil2cpp.so")  # engine -> Unity, fires the gate
    _seed_container(ws)
    body = b"u=https://gate.example.com/x"
    monkeypatch.setattr(unityasset, "available", lambda: True)
    monkeypatch.setattr(unityasset, "parse_container", lambda path, rel, **kw: [_es(body.decode(), raw=body)])
    findings = run_all(ws, use_cache=False)
    assert any(f.kind == "endpoint" and f.subject == "gate.example.com" for f in findings)


def test_unity_assets_rerun_reproduces_dumps(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """unity_assets is uncached (writes artifacts): a second run reproduces the dumps."""
    ws = _ws(tmp_path)
    _seed_container(ws)
    body = b"https://rerun.example.com/y"
    monkeypatch.setattr(unityasset, "available", lambda: True)
    monkeypatch.setattr(unityasset, "parse_container", lambda path, rel, **kw: [_es(body.decode(), raw=body)])
    assets_scanner.scan(ws)
    assets_scanner.scan(ws)
    on_disk = list((ws.dumps_dir / "unity" / "assets").iterdir())
    assert on_disk and on_disk[0].read_bytes() == body


def test_ress_endpoint_swept(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "data/stream.resS",
           b"\x00\x01\x02 https://stream.example.com/v1/track padding")
    findings = assets_scanner._ress_endpoints(ws)
    assert any(f.kind == "endpoint" and f.subject == "stream.example.com" for f in findings)


def test_ress_media_skipped(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    # an OggS-magic .resS is audio noise -> skipped, its URL not harvested
    _touch(ws.extracted_dir, "audio/music.resS", b"OggS\x00\x02 https://hidden.example.com/x")
    assert assets_scanner._ress_endpoints(ws) == []


def test_unity_key_threaded_to_parse_container(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = bytes(range(16))
    monkeypatch.setenv("DUMPA_UNITY_KEY", "0x" + key.hex())
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "data.assets")
    seen: dict[str, object] = {}

    def fake(path: Path, rel: str, **kw: object) -> list:
        seen["key"] = kw.get("decrypt_key")
        return []

    monkeypatch.setattr(unityasset, "available", lambda: True)
    monkeypatch.setattr(unityasset, "parse_container", fake)
    assets_scanner.scan(ws)
    assert seen["key"] == key                          # DUMPA_UNITY_KEY reached parse_container
