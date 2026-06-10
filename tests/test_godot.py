"""Godot deep-helper scanner (godot) and its gate in run_all."""

from __future__ import annotations

from pathlib import Path

from _pck_build import build_pck, build_pck_v2_encrypted, embed_in_binary

from dumpa.core.report import FindingState
from dumpa.core.workspace import Workspace, make_meta
from dumpa.scanners import godot, run_all

_SHA = "d" * 64
_FILES = {
    "res://scenes/main.tscn": b"[gd_scene]\n",
    "res://scripts/player.gd": b"extends Node\n",
}


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


def _touch(root: Path, rel: str, data: bytes) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _mark_reusable(ws: Workspace) -> None:
    ws.write_meta(make_meta(
        input_path=Path("app.apk"), input_sha256=_SHA, input_size=1,
        input_type="apk", tool_versions={}))


def test_standalone_pck_listed_and_extracted(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "assets/game.pck", build_pck(_FILES, version=(3, 5, 2)))
    findings = godot.scan(ws)
    subjects = {f.subject for f in findings}
    assert "Godot version 3.5.2" in subjects
    assert any(s.startswith("Godot PCK: assets/game.pck") for s in subjects)
    assert any(s.startswith("Godot resources extracted (2)") for s in subjects)
    assert (ws.dumps_dir / "godot" / "pck" / "game" / "scenes/main.tscn").read_bytes() \
        == _FILES["res://scenes/main.tscn"]
    assert (ws.dumps_dir / "godot" / ".dumpa-godot.json").is_file()


def test_embedded_pck_located_and_extracted(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    blob = embed_in_binary(b"\x7fELF stub godot native lib ........", build_pck(_FILES))
    _touch(ws.extracted_dir, "lib/arm64-v8a/libgodot.so", blob)
    findings = godot.scan(ws)
    assert any(s.startswith("Godot PCK: lib/arm64-v8a/libgodot.so") for s in
               {f.subject for f in findings})
    assert (ws.dumps_dir / "godot" / "pck" / "libgodot" / "scripts/player.gd").read_bytes() \
        == _FILES["res://scripts/player.gd"]


def test_v2_encrypted_pck_deferred(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "assets/game4.pck", build_pck_v2_encrypted())
    findings = godot.scan(ws)
    deferred = next(f for f in findings if f.subject.startswith("Godot PCK deferred"))
    assert deferred.state == FindingState.PRESENT
    assert not any(f.subject.startswith("Godot resources extracted") for f in findings)
    assert not (ws.dumps_dir / "godot" / "pck").exists()


def test_config_and_gdc_reported(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "assets/game.pck", build_pck(_FILES))
    _touch(ws.extracted_dir, "assets/project.binary", b"\x00config\x00")
    _touch(ws.extracted_dir, "assets/scripts/main.gdc", b"\x00bytecode")
    subjects = {f.subject for f in godot.scan(ws)}
    assert "Godot config: project.binary" in subjects
    assert any(s.startswith("Godot GDScript bytecode (1") for s in subjects)


def test_config_endpoints_harvested_from_pck(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    files = {
        "res://project.godot": b'[network]\nserver="https://api.mygame.example/v1/login"\n',
        "res://scenes/main.tscn": b"[gd_scene]\n",
    }
    _touch(ws.extracted_dir, "assets/game.pck", build_pck(files, version=(3, 5, 2)))
    findings = godot.scan(ws)
    ep = next((f for f in findings if f.kind == "endpoint"), None)
    assert ep is not None
    assert ep.subject == "api.mygame.example"
    assert ep.locations[0].domain == "api.mygame.example"
    assert ep.locations[0].file_path.startswith("dumps/godot/pck/")


def test_non_godot_app_is_noop(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libunity.so", b"\x00")
    assert godot.scan(ws) == []


def test_gate_fires_only_for_godot(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "assets/game.pck", build_pck(_FILES))
    subjects = {f.subject for f in run_all(ws, use_cache=False)}
    assert "Godot" in subjects                              # engine detection
    assert "Godot version 3.5.0" in subjects                # deep helper fired

    other = _ws(tmp_path / "x")
    _touch(other.extracted_dir, "lib/arm64-v8a/libunity.so", b"\x00")
    subjects2 = {f.subject for f in run_all(other, use_cache=False)}
    assert not any(s.startswith("Godot") for s in subjects2)


def test_cached_run_all_recreates_extracted_resources(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _mark_reusable(ws)
    _touch(ws.extracted_dir, "assets/game.pck", build_pck(_FILES))
    out = ws.dumps_dir / "godot" / "pck" / "game" / "scenes/main.tscn"

    run_all(ws)
    assert out.read_bytes() == _FILES["res://scenes/main.tscn"]

    out.unlink()
    run_all(ws)
    assert out.read_bytes() == _FILES["res://scenes/main.tscn"]
