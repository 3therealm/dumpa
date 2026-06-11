"""UE4 `.pak` parser: footer + legacy index parse, extraction, defer paths."""

from __future__ import annotations

from pathlib import Path

import pytest
from _unrealpak_build import (
    build_pak,
    build_pak_encrypted_index,
    build_pak_pathhash_index,
)

from dumpa.core import unrealpak

_FILES = {
    "Config/DefaultEngine.ini": b"[URL]\nServer=https://api.example.test/v1\n",
    "Content/data.json": b'{"endpoint":"https://cdn.example.test/assets"}',
}


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "game.pak"
    p.write_bytes(data)
    return p


def test_footer_and_legacy_index_parse(tmp_path: Path) -> None:
    pak = unrealpak.parse_standalone(_write(tmp_path, build_pak(_FILES)))
    assert pak is not None
    assert pak.version == 8
    assert pak.mount_point == "../../../Game/"
    assert pak.deferred_reason is None
    assert {e.path for e in pak.entries} == set(_FILES)
    assert all(e.compression == "none" for e in pak.entries)


def test_uncompressed_extract_roundtrip(tmp_path: Path) -> None:
    path = _write(tmp_path, build_pak(_FILES))
    pak = unrealpak.parse_standalone(path)
    assert pak is not None
    out = tmp_path / "out"
    assert unrealpak.extract(path, pak, out) == 2
    assert (out / "Config/DefaultEngine.ini").read_bytes() == _FILES["Config/DefaultEngine.ini"]
    assert (out / "Content/data.json").read_bytes() == _FILES["Content/data.json"]


def test_extract_skips_entries_over_file_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write(tmp_path, build_pak({"small.txt": b"ok", "large.txt": b"too large"}))
    pak = unrealpak.parse_standalone(path)
    assert pak is not None
    monkeypatch.setattr(unrealpak, "const_max_extract_file_bytes", 4)
    out = tmp_path / "out"

    assert unrealpak.extract(path, pak, out) == 1
    assert (out / "small.txt").read_bytes() == b"ok"
    assert not (out / "large.txt").exists()


def test_zlib_extract_roundtrip(tmp_path: Path) -> None:
    path = _write(tmp_path, build_pak(_FILES, compress="zlib"))
    pak = unrealpak.parse_standalone(path)
    assert pak is not None
    assert all(e.compression == "zlib" for e in pak.entries)
    out = tmp_path / "out"
    assert unrealpak.extract(path, pak, out) == 2
    assert (out / "Content/data.json").read_bytes() == _FILES["Content/data.json"]


def test_gzip_extract_roundtrip(tmp_path: Path) -> None:
    path = _write(tmp_path, build_pak(_FILES, compress="gzip"))
    pak = unrealpak.parse_standalone(path)
    assert pak is not None
    assert all(e.compression == "gzip" for e in pak.entries)
    out = tmp_path / "out"
    assert unrealpak.extract(path, pak, out) == 2
    assert (out / "Config/DefaultEngine.ini").read_bytes() == _FILES["Config/DefaultEngine.ini"]


def test_oodle_method_deferred_per_entry(tmp_path: Path) -> None:
    # method_override=3 -> "Oodle" in the table; entries parse but must not extract.
    path = _write(tmp_path, build_pak(_FILES, compress="zlib", method_override=3))
    pak = unrealpak.parse_standalone(path)
    assert pak is not None
    assert all(e.compression == "oodle" for e in pak.entries)
    out = tmp_path / "out"
    assert unrealpak.extract(path, pak, out) == 0
    assert not out.exists()


def test_encrypted_entries_not_extracted(tmp_path: Path) -> None:
    path = _write(tmp_path, build_pak(_FILES, encrypt_entries=True))
    pak = unrealpak.parse_standalone(path)
    assert pak is not None
    assert all(e.encrypted for e in pak.entries)
    out = tmp_path / "out"
    assert unrealpak.extract(path, pak, out) == 0


def test_encrypted_index_deferred(tmp_path: Path) -> None:
    pak = unrealpak.parse_standalone(_write(tmp_path, build_pak_encrypted_index()))
    assert pak is not None
    assert pak.index_encrypted is True
    assert unrealpak.is_deferred(pak)
    assert pak.entries == []


def test_pathhash_index_deferred(tmp_path: Path) -> None:
    pak = unrealpak.parse_standalone(_write(tmp_path, build_pak_pathhash_index(version=11)))
    assert pak is not None
    assert pak.version == 11
    assert unrealpak.is_deferred(pak)
    assert "v11" in (pak.deferred_reason or "")


def test_path_traversal_rejected(tmp_path: Path) -> None:
    evil = {"../../escape.txt": b"nope", "Content/ok.txt": b"ok"}
    path = _write(tmp_path, build_pak(evil))
    pak = unrealpak.parse_standalone(path)
    assert pak is not None
    out = tmp_path / "out"
    assert unrealpak.extract(path, pak, out) == 1            # only the safe entry
    assert (out / "Content/ok.txt").read_bytes() == b"ok"
    assert not (tmp_path / "escape.txt").exists()


def test_not_a_pak_returns_none(tmp_path: Path) -> None:
    assert unrealpak.parse_standalone(_write(tmp_path, b"not a pak file at all")) is None
