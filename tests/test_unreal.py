"""Unreal deep-helper scanner (unreal) and its gate in run_all."""

from __future__ import annotations

from pathlib import Path

from _unrealpak_build import build_pak, build_pak_encrypted_index

from dumpa.core.workspace import Workspace, make_meta
from dumpa.scanners import run_all, unreal

_SHA = "e" * 64
_FILES = {
    "Config/DefaultEngine.ini": b'[URL]\nServer=https://api.mygame.example/v1/login\n',
    "Content/notes.txt": b"hello",
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


def test_standalone_pak_listed_and_extracted(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "base/Game.pak", build_pak(_FILES))
    findings = unreal.scan(ws)
    subjects = {f.subject for f in findings}
    assert "Unreal Engine pak version 8" in subjects
    assert any(s.startswith("Unreal pak: base/Game.pak") for s in subjects)
    assert any(s.startswith("Unreal pak extracted (2)") for s in subjects)
    assert (ws.dumps_dir / "unreal" / "pak" / "Game" / "Content/notes.txt").read_bytes() == b"hello"
    assert (ws.dumps_dir / "unreal" / ".dumpa-unreal.json").is_file()


def test_endpoints_harvested_from_pak_config(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "base/Game.pak", build_pak(_FILES))
    findings = unreal.scan(ws)
    ep = next((f for f in findings if f.kind == "endpoint"), None)
    assert ep is not None
    assert ep.subject == "api.mygame.example"
    assert ep.locations[0].domain == "api.mygame.example"
    assert ep.locations[0].file_path.startswith("dumps/unreal/pak/")


def test_encrypted_index_pak_deferred(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "base/Game.pak", build_pak_encrypted_index())
    findings = unreal.scan(ws)
    assert any(f.subject.startswith("Unreal pak deferred") for f in findings)
    assert not any(f.subject.startswith("Unreal pak extracted") for f in findings)
    assert not (ws.dumps_dir / "unreal" / "pak").exists()


def test_iostore_toc_enumerated(tmp_path: Path) -> None:
    from _iostore_build import FLAG_COMPRESSED, FLAG_ENCRYPTED, build_toc
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "base/global.utoc",
           build_toc(entry_count=7, flags=FLAG_COMPRESSED | FLAG_ENCRYPTED))
    findings = unreal.scan(ws)
    toc_f = next(f for f in findings if f.subject.startswith("Unreal IoStore"))
    assert "7 chunks" in toc_f.subject
    assert toc_f.attributes["encrypted"] == "True"


def test_non_unreal_app_is_noop(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libunity.so", b"\x00")
    assert unreal.scan(ws) == []


def test_gate_fires_only_for_unreal(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "base/Game.pak", build_pak(_FILES))
    subjects = {f.subject for f in run_all(ws, use_cache=False)}
    assert "Unreal Engine" in subjects                      # engine detection
    assert "Unreal Engine pak version 8" in subjects        # deep helper fired

    other = _ws(tmp_path / "x")
    _touch(other.extracted_dir, "lib/arm64-v8a/libunity.so", b"\x00")
    subjects2 = {f.subject for f in run_all(other, use_cache=False)}
    assert not any(s.startswith("Unreal") for s in subjects2)


def test_cached_run_all_recreates_extracted_resources(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _mark_reusable(ws)
    _touch(ws.extracted_dir, "base/Game.pak", build_pak(_FILES))
    out = ws.dumps_dir / "unreal" / "pak" / "Game" / "Content/notes.txt"

    run_all(ws)
    assert out.read_bytes() == b"hello"

    out.unlink()
    run_all(ws)
    assert out.read_bytes() == b"hello"
