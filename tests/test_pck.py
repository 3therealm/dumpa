"""Tests for the zero-dep Godot PCK parser (core.pck)."""

from __future__ import annotations

from pathlib import Path

from _pck_build import build_pck, build_pck_v2_encrypted, embed_in_binary

from dumpa.core.pck import extract, find_embedded, is_encrypted, parse_at, parse_standalone

_FILES = {
    "res://scenes/main.tscn": b"[gd_scene]\n",
    "res://scripts/player.gd": b"extends Node\nfunc _ready():\n\tpass\n",
}


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def test_parse_standalone(tmp_path: Path) -> None:
    pck = _write(tmp_path, "game.pck", build_pck(_FILES, version=(3, 5, 2)))
    parsed = parse_standalone(pck)
    assert parsed is not None
    assert parsed.fmt_version == 1
    assert parsed.godot_version == (3, 5, 2)
    assert {e.path for e in parsed.entries} == set(_FILES)
    assert not is_encrypted(parsed)


def test_extract_round_trips_contents(tmp_path: Path) -> None:
    pck = _write(tmp_path, "game.pck", build_pck(_FILES))
    parsed = parse_standalone(pck)
    out = tmp_path / "out"
    n = extract(pck, parsed, out)
    assert n == len(_FILES)
    assert (out / "scenes/main.tscn").read_bytes() == _FILES["res://scenes/main.tscn"]
    assert (out / "scripts/player.gd").read_bytes() == _FILES["res://scripts/player.gd"]


def test_find_embedded_locates_offset(tmp_path: Path) -> None:
    inner = build_pck(_FILES)
    blob = embed_in_binary(b"\x7fELF stub native library bytes ......", inner)
    so = _write(tmp_path, "libgodot.so", blob)
    start = find_embedded(so)
    assert start == len(b"\x7fELF stub native library bytes ......")
    parsed = parse_at(so, start)
    assert parsed is not None
    assert {e.path for e in parsed.entries} == set(_FILES)
    # entry data resolves through base_offset, so extraction still works embedded
    out = tmp_path / "emb"
    assert extract(so, parsed, out) == len(_FILES)
    assert (out / "scenes/main.tscn").read_bytes() == _FILES["res://scenes/main.tscn"]


def test_no_embedded_pck_returns_none(tmp_path: Path) -> None:
    so = _write(tmp_path, "libplain.so", b"\x7fELF" + b"\x00" * 200)
    assert find_embedded(so) is None


def test_v2_encrypted_flagged_and_not_extracted(tmp_path: Path) -> None:
    pck = _write(tmp_path, "game4.pck", build_pck_v2_encrypted())
    parsed = parse_standalone(pck)
    assert parsed is not None
    assert parsed.fmt_version == 2
    assert is_encrypted(parsed)
    assert extract(pck, parsed, tmp_path / "out4") == 0      # deferred: nothing written


def test_bogus_file_count_rejected(tmp_path: Path) -> None:
    blob = bytearray(build_pck(_FILES))
    # file_count sits right after the 20-byte version block + 64 reserved bytes.
    import struct
    struct.pack_into("<I", blob, 20 + 64, 0xFFFFFFFF)
    pck = _write(tmp_path, "bad.pck", bytes(blob))
    assert parse_standalone(pck) is None


def test_path_traversal_not_written(tmp_path: Path) -> None:
    pck = _write(tmp_path, "evil.pck", build_pck({"res://../../etc/passwd": b"x"}))
    parsed = parse_standalone(pck)
    out = tmp_path / "out"
    assert extract(pck, parsed, out) == 0
    assert not (tmp_path / "etc" / "passwd").exists()
    assert not (out / "etc" / "passwd").exists()
