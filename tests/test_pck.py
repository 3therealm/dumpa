"""Tests for the zero-dep Godot PCK parser (core.pck)."""

from __future__ import annotations

from pathlib import Path

import pytest
from _pck_build import (
    GODOT_KEY,
    build_pck,
    build_pck_v2_encrypted,
    build_pck_v4,
    embed_in_binary,
)

from dumpa.core import pck as pck_core
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


def test_extract_skips_entries_over_file_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pck = _write(tmp_path, "game.pck", build_pck({
        "res://small.txt": b"ok",
        "res://large.txt": b"too large",
    }))
    parsed = parse_standalone(pck)
    assert parsed is not None
    monkeypatch.setattr(pck_core, "const_max_extract_file_bytes", 4)
    out = tmp_path / "out"

    assert extract(pck, parsed, out) == 1
    assert (out / "small.txt").read_bytes() == b"ok"
    assert not (out / "large.txt").exists()


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


def test_excessive_file_count_rejected(tmp_path: Path) -> None:
    blob = bytearray(build_pck(_FILES))
    import struct
    struct.pack_into("<I", blob, 20 + 64, 200_000)      # over the 100k anti-DoS cap
    pck = _write(tmp_path, "many.pck", bytes(blob))
    assert parse_standalone(pck) is None


def test_extract_bare_paths_without_res_prefix(tmp_path: Path) -> None:
    # Godot's packer strips the res:// prefix; paths are stored bare. Extraction still works.
    pck = _write(tmp_path, "bare.pck", build_pck({"scenes/main.tscn": b"x", "a.txt": b"y"}))
    parsed = parse_standalone(pck)
    assert parsed is not None
    assert {e.path for e in parsed.entries} == {"scenes/main.tscn", "a.txt"}
    out = tmp_path / "out"
    assert extract(pck, parsed, out) == 2
    assert (out / "scenes/main.tscn").read_bytes() == b"x"
    assert (out / "a.txt").read_bytes() == b"y"


def test_removal_entries_dropped_from_inventory(tmp_path: Path) -> None:
    from dumpa.core.pck import PACK_FILE_REMOVAL
    blob = build_pck_v4({"res://keep.txt": b"keep", "res://gone.txt": b"gone"}, fmt=4,
                        entry_flags={"res://gone.txt": PACK_FILE_REMOVAL})
    pck = _write(tmp_path, "patch.pck", blob)
    parsed = parse_standalone(pck)
    assert parsed is not None
    assert {e.path for e in parsed.entries} == {"res://keep.txt"}      # removal entry dropped


def test_path_traversal_not_written(tmp_path: Path) -> None:
    pck = _write(tmp_path, "evil.pck", build_pck({"res://../../etc/passwd": b"x"}))
    parsed = parse_standalone(pck)
    out = tmp_path / "out"
    assert extract(pck, parsed, out) == 0
    assert not (tmp_path / "etc" / "passwd").exists()
    assert not (out / "etc" / "passwd").exists()


# Godot 4 v2-v4 packs. "res://a.txt" has an unaligned path length, exercising the 4-byte
# path padding in the v2-v4 entry layout.
_V4_FILES = {
    "res://a.txt": b"alpha",
    "res://nested/dir/b.bin": b"bravo-bytes",
}


def test_v2_unencrypted_parse_and_extract(tmp_path: Path) -> None:
    pck = _write(tmp_path, "g2.pck", build_pck_v4(_V4_FILES, fmt=2, version=(4, 0, 0)))
    parsed = parse_standalone(pck)
    assert parsed is not None
    assert parsed.fmt_version == 2
    assert not is_encrypted(parsed)
    assert {e.path for e in parsed.entries} == set(_V4_FILES)
    out = tmp_path / "out2"
    assert extract(pck, parsed, out) == len(_V4_FILES)
    assert (out / "a.txt").read_bytes() == b"alpha"
    assert (out / "nested/dir/b.bin").read_bytes() == b"bravo-bytes"


def test_v4_unencrypted_parse_and_extract(tmp_path: Path) -> None:
    pck = _write(tmp_path, "g4.pck", build_pck_v4(_V4_FILES, fmt=4))
    parsed = parse_standalone(pck)
    assert parsed is not None
    assert parsed.fmt_version == 4
    assert {e.path for e in parsed.entries} == set(_V4_FILES)
    out = tmp_path / "out4"
    assert extract(pck, parsed, out) == len(_V4_FILES)
    assert (out / "a.txt").read_bytes() == b"alpha"


def test_v4_encrypted_directory_needs_key(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    blob = build_pck_v4(_V4_FILES, fmt=4, key=GODOT_KEY, enc_dir=True)
    pck = _write(tmp_path, "enc.pck", blob)

    # No key: directory is opaque, pack is deferred, nothing extracted.
    no_key = parse_standalone(pck)
    assert no_key is not None
    assert is_encrypted(no_key)
    assert no_key.deferred_reason is not None
    assert no_key.entries == []
    assert extract(pck, no_key, tmp_path / "nokey") == 0

    # With the key: directory decrypts, entries parse, files extract.
    keyed = parse_standalone(pck, GODOT_KEY)
    assert keyed is not None
    assert keyed.deferred_reason is None
    assert {e.path for e in keyed.entries} == set(_V4_FILES)
    out = tmp_path / "keyed"
    assert extract(pck, keyed, out, GODOT_KEY) == len(_V4_FILES)
    assert (out / "a.txt").read_bytes() == b"alpha"


def test_v4_wrong_key_defers(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    pck = _write(tmp_path, "enc.pck", build_pck_v4(_V4_FILES, fmt=4, key=GODOT_KEY, enc_dir=True))
    wrong = bytes(range(1, 33))
    parsed = parse_standalone(pck, wrong)
    assert parsed is not None
    assert parsed.deferred_reason is not None       # MD5 verify fails -> deferred, not a crash
    assert parsed.entries == []


def test_read_fae_rejects_length_mismatch() -> None:
    pytest.importorskip("cryptography")
    import io

    from _pck_build import _fae_wrap

    from dumpa.core.pck import _read_fae
    blob = _fae_wrap(b"x" * 100, GODOT_KEY)
    # A wrapper claiming a different plaintext length than the directory entry is rejected
    # up front (before the ciphertext is read), guarding against a hostile size.
    assert _read_fae(io.BytesIO(blob).read, GODOT_KEY, expected_len=5) is None
    assert _read_fae(io.BytesIO(blob).read, GODOT_KEY, expected_len=100) == b"x" * 100
    # max_len caps the accepted length up front (the directory path uses a per-count bound).
    assert _read_fae(io.BytesIO(blob).read, GODOT_KEY, max_len=50) is None
    assert _read_fae(io.BytesIO(blob).read, GODOT_KEY, max_len=100) == b"x" * 100


def test_v4_zero_length_encrypted_entry(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    # Godot's FileAccessEncrypted wraps zero-length files (md5 | len=0 | iv | empty ct).
    blob = build_pck_v4({"res://empty.dat": b""}, fmt=4, key=GODOT_KEY, enc_files=True)
    pck = _write(tmp_path, "empty.pck", blob)
    parsed = parse_standalone(pck, GODOT_KEY)
    assert parsed is not None
    out = tmp_path / "out"
    assert extract(pck, parsed, out, GODOT_KEY) == 1
    assert (out / "empty.dat").read_bytes() == b""


def test_v4_per_file_encrypted_entries(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    blob = build_pck_v4(_V4_FILES, fmt=4, key=GODOT_KEY, enc_files=True)
    pck = _write(tmp_path, "encfiles.pck", blob)
    parsed = parse_standalone(pck, GODOT_KEY)
    assert parsed is not None
    assert parsed.deferred_reason is None
    assert {e.path for e in parsed.entries} == set(_V4_FILES)

    # Without the key, encrypted entries are skipped (not written); with it, they decrypt.
    assert extract(pck, parsed, tmp_path / "nokey") == 0
    out = tmp_path / "keyed"
    assert extract(pck, parsed, out, GODOT_KEY) == len(_V4_FILES)
    assert (out / "a.txt").read_bytes() == b"alpha"
    assert (out / "nested/dir/b.bin").read_bytes() == b"bravo-bytes"
