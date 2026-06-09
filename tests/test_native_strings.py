"""Per-library/ABI native string dump (native-strings finding + sidecar)."""

from __future__ import annotations

import json
from pathlib import Path

from _elf_build import build_elf

from dumpa.core.workspace import Workspace
from dumpa.scanners import native as native_scanner

# build_elf lays out ehdr(64) | phdr(56) | payload | ... for a 64-bit LE object,
# so the payload always starts at this fixed file offset.
_PAYLOAD_OFF = 64 + 56


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


def _write_so(ws: Workspace, abi: str, name: str, payload: bytes) -> None:
    d = ws.extracted_dir / "lib" / abi
    d.mkdir(parents=True, exist_ok=True)
    data, off = build_elf(payload=payload)
    assert off == _PAYLOAD_OFF
    (d / name).write_bytes(data)


def test_native_strings_finding_and_sidecar(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    # "HELLO_WORLD" (>=5) kept; "ab" (<5) dropped; "another_string" kept.
    payload = b"\x00HELLO_WORLD\x00\x00ab\x00another_string\x00"
    _write_so(ws, "arm64-v8a", "liby.so", payload)

    findings = native_scanner.scan(ws)
    strs = [f for f in findings if f.kind == "native-strings"]
    assert len(strs) == 1
    f = strs[0]
    assert f.subject == "arm64-v8a/liby.so"
    assert f.attributes["abi"] == "arm64-v8a"

    sidecar = ws.root / f.attributes["sidecar"]
    assert sidecar.is_file()
    data = json.loads(sidecar.read_text(encoding="UTF-8"))
    assert data["abi"] == "arm64-v8a"
    assert data["lib"] == "liby.so"
    assert data["truncated"] is False
    assert data["count"] == int(f.attributes["string_count"])

    texts = {s["text"]: s["offset"] for s in data["strings"]}
    assert "HELLO_WORLD" in texts
    assert texts["HELLO_WORLD"] == _PAYLOAD_OFF + 1   # one NUL of lead-in
    assert "another_string" in texts
    assert "ab" not in texts                          # below _STR_MIN_LEN


def test_native_strings_sidecar_is_not_a_symbol_sidecar(tmp_path: Path) -> None:
    # The strings dump must land in a sibling dir, so xref/diff's native/*.json
    # glob never picks it up.
    ws = _ws(tmp_path)
    _write_so(ws, "arm64-v8a", "liby.so", b"\x00READABLE_STRING\x00")
    native_scanner.scan(ws)
    assert list(ws.native_strings_dir.glob("*.strings.json"))
    assert not list(ws.native_dir.glob("*.strings.json"))


def test_native_strings_spanning_chunk_boundary(tmp_path: Path) -> None:
    # A run straddling the 1 MiB read boundary must still be captured intact at its
    # true offset (exercises the deferred-match / overlap edge-guard).
    boundary = native_scanner._STR_CHUNK            # 1 << 20
    marker = b"BOUNDARYMARK"
    start_abs = boundary - 4                         # 4 bytes before the edge
    start_idx = start_abs - _PAYLOAD_OFF
    payload = bytearray(start_idx) + marker + b"\x00"
    _write_so(ws := _ws(tmp_path), "arm64-v8a", "libb.so", bytes(payload))

    findings = native_scanner.scan(ws)
    f = next(f for f in findings if f.kind == "native-strings")
    data = json.loads((ws.root / f.attributes["sidecar"]).read_text(encoding="UTF-8"))
    texts = {s["text"]: s["offset"] for s in data["strings"]}
    assert texts.get("BOUNDARYMARK") == start_abs
