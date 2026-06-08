"""Cocos2d-x deep-helper scanner (cocos) and its gate in run_all."""

from __future__ import annotations

from pathlib import Path

from _xxtea_build import make_signed

from dumpa.core.report import FindingState
from dumpa.core.workspace import Workspace, make_meta
from dumpa.scanners import cocos, run_all

_SHA = "c" * 64
_KEY = b"my-secret-key-16"
_SIGN = b"XXTEA"
_SCRIPT = b'cc.log("hello from a cocos script");\nvar x = 1 + 2;\n' * 4


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


def _touch(root: Path, rel: str, data: bytes) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _lib_with_key(key: bytes) -> bytes:
    # The harvester only looks within a window of the setXXTEAKeyAndSign marker, so the
    # key string must sit beside it (as it does in a real .rodata literal pool).
    return b"\x00" * 64 + b"setXXTEAKeyAndSign\x00" + key + b"\x00" + _SIGN + b"\x00pad"


def _cocos_app(tmp_path: Path, *, with_key: bool) -> Workspace:
    ws = _ws(tmp_path)
    key_in_lib = _KEY if with_key else b"not-the-real-key"
    _touch(ws.extracted_dir, "lib/arm64-v8a/libcocos2djs.so",
           b"junk cocos2d-x 3.17.2 junk " + _lib_with_key(key_in_lib))
    _touch(ws.extracted_dir, "assets/src/game.jsc", make_signed(_SCRIPT, _KEY, _SIGN))
    return ws


def _mark_reusable(ws: Workspace) -> None:
    ws.write_meta(make_meta(
        input_path=Path("app.apk"), input_sha256=_SHA, input_size=1,
        input_type="apk", tool_versions={}))


def test_reports_scripting_and_version(tmp_path: Path) -> None:
    findings = cocos.scan(_cocos_app(tmp_path, with_key=True))
    subjects = {f.subject for f in findings}
    assert "Cocos2d-x scripting: JavaScript" in subjects
    assert "Cocos2d-x version 3.17.2" in subjects


def test_decrypts_bundles_when_key_found(tmp_path: Path) -> None:
    ws = _cocos_app(tmp_path, with_key=True)
    findings = cocos.scan(ws)
    assert any(f.subject == "Cocos2d-x XXTEA key recovered" for f in findings)
    assert any(f.subject.startswith("Cocos2d-x scripts decrypted") for f in findings)
    out = ws.dumps_dir / "cocos" / "decrypted" / "assets/src/game.js"
    assert out.is_file()
    assert out.read_bytes() == _SCRIPT
    sidecar = ws.dumps_dir / "cocos" / ".dumpa-cocos.json"
    assert sidecar.is_file()


def test_key_material_not_in_findings(tmp_path: Path) -> None:
    findings = cocos.scan(_cocos_app(tmp_path, with_key=True))
    for f in findings:
        blob = repr(f)
        assert _KEY.decode() not in blob
    # the recovered-key finding reports the source path, not the key bytes
    rec = next(f for f in findings if f.subject == "Cocos2d-x XXTEA key recovered")
    assert rec.attributes["key_source"].endswith("libcocos2djs.so")
    assert "key_hex" not in rec.attributes


def test_no_key_reports_encrypted_no_writes(tmp_path: Path) -> None:
    ws = _cocos_app(tmp_path, with_key=False)
    findings = cocos.scan(ws)
    assert any("encrypted" in f.subject for f in findings)
    assert not any(f.subject.startswith("Cocos2d-x scripts decrypted") for f in findings)
    assert not (ws.dumps_dir / "cocos" / "decrypted").exists()


def test_non_cocos_app_is_noop(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _touch(ws.extracted_dir, "lib/arm64-v8a/libunity.so", b"\x00")
    assert cocos.scan(ws) == []


def test_encrypted_finding_state(tmp_path: Path) -> None:
    findings = cocos.scan(_cocos_app(tmp_path, with_key=False))
    enc = next(f for f in findings if "encrypted" in f.subject)
    assert enc.state == FindingState.PRESENT


def test_gate_fires_only_for_cocos(tmp_path: Path) -> None:
    # run_all should run the cocos helper because engine detection flags Cocos2d-x.
    ws = _cocos_app(tmp_path, with_key=True)
    subjects = {f.subject for f in run_all(ws, use_cache=False)}
    assert "Cocos2d-x" in subjects                       # engine detection
    assert "Cocos2d-x scripting: JavaScript" in subjects  # deep helper fired

    # a non-cocos workspace never runs the helper.
    other = _ws(tmp_path / "x")
    _touch(other.extracted_dir, "lib/arm64-v8a/libunity.so", b"\x00")
    subjects2 = {f.subject for f in run_all(other, use_cache=False)}
    assert not any(s.startswith("Cocos2d-x") for s in subjects2)


def test_cached_run_all_recreates_decrypted_artifacts(tmp_path: Path) -> None:
    ws = _cocos_app(tmp_path, with_key=True)
    _mark_reusable(ws)
    out = ws.dumps_dir / "cocos" / "decrypted" / "assets/src/game.js"

    run_all(ws)
    assert out.read_bytes() == _SCRIPT

    out.unlink()
    run_all(ws)
    assert out.read_bytes() == _SCRIPT
