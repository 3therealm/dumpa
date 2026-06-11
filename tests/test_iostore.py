"""UE5 IoStore `.utoc`/`.ucas` parser + non-Oodle extractor."""

from __future__ import annotations

from pathlib import Path

import pytest
from _iostore_build import (
    FLAG_COMPRESSED,
    FLAG_ENCRYPTED,
    FLAG_INDEXED,
    build_iostore,
    build_toc,
)

from dumpa.core import iostore

_FILES = {
    "Config/DefaultEngine.ini": b"[URL]\nServer=https://api.example.test/v1\n",
    "Content/data.json": b'{"endpoint":"https://cdn.example.test/assets"}',
}
_AES_KEY = bytes(range(32))


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "global.utoc"
    p.write_bytes(data)
    return p


def _write_pair(tmp_path: Path, utoc: bytes, ucas: bytes) -> Path:
    (tmp_path / "global.ucas").write_bytes(ucas)
    return _write(tmp_path, utoc)


def test_header_parse(tmp_path: Path) -> None:
    flags = FLAG_COMPRESSED | FLAG_INDEXED
    toc = iostore.parse_toc(_write(tmp_path, build_toc(version=3, entry_count=42, flags=flags)))
    assert toc is not None
    assert toc.version == 3
    assert toc.entry_count == 42
    assert toc.compressed is True
    assert toc.indexed is True
    assert toc.encrypted is False


def test_encrypted_flag(tmp_path: Path) -> None:
    toc = iostore.parse_toc(_write(tmp_path, build_toc(flags=FLAG_COMPRESSED | FLAG_ENCRYPTED)))
    assert toc is not None
    assert toc.encrypted is True


def test_extract_is_deferred(tmp_path: Path) -> None:
    path = _write(tmp_path, build_toc())
    toc = iostore.parse_toc(path)
    assert toc is not None
    assert iostore.extract(path, toc, tmp_path / "out") == 0
    assert not (tmp_path / "out").exists()


def test_not_a_toc_returns_none(tmp_path: Path) -> None:
    assert iostore.parse_toc(_write(tmp_path, b"not an iostore toc header")) is None


# --- full parse + non-Oodle extraction ---------------------------------------

def test_uncompressed_parse_and_extract(tmp_path: Path) -> None:
    utoc, ucas = build_iostore(_FILES)
    path = _write_pair(tmp_path, utoc, ucas)
    toc = iostore.parse_toc(path)
    assert toc is not None
    assert {tf.path for tf in toc.files} == set(_FILES)        # directory index -> real paths
    out = tmp_path / "out"
    assert iostore.extract(path, toc, out) == 2
    assert (out / "Config/DefaultEngine.ini").read_bytes() == _FILES["Config/DefaultEngine.ini"]
    assert (out / "Content/data.json").read_bytes() == _FILES["Content/data.json"]


def test_extract_skips_chunks_over_file_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    utoc, ucas = build_iostore({"Config/DefaultEngine.ini": b"too large"})
    path = _write_pair(tmp_path, utoc, ucas)
    toc = iostore.parse_toc(path)
    assert toc is not None
    monkeypatch.setattr(iostore, "const_max_extract_file_bytes", 4)
    out = tmp_path / "out"

    assert iostore.extract(path, toc, out) == 0
    assert not (out / "Config/DefaultEngine.ini").exists()


def test_zlib_parse_and_extract(tmp_path: Path) -> None:
    utoc, ucas = build_iostore(_FILES, compress="zlib")
    path = _write_pair(tmp_path, utoc, ucas)
    toc = iostore.parse_toc(path)
    assert toc is not None
    assert toc.compression_methods == ["Zlib"]                  # real method name surfaced
    out = tmp_path / "out"
    assert iostore.extract(path, toc, out) == 2
    assert (out / "Content/data.json").read_bytes() == _FILES["Content/data.json"]


def test_lz4_parse_and_extract(tmp_path: Path) -> None:
    pytest.importorskip("lz4")
    utoc, ucas = build_iostore(_FILES, compress="lz4")
    path = _write_pair(tmp_path, utoc, ucas)
    toc = iostore.parse_toc(path)
    assert toc is not None
    out = tmp_path / "out"
    assert iostore.extract(path, toc, out) == 2
    assert (out / "Content/data.json").read_bytes() == _FILES["Content/data.json"]


def test_oodle_listed_but_deferred(tmp_path: Path) -> None:
    utoc, ucas = build_iostore(_FILES, compress="oodle")
    path = _write_pair(tmp_path, utoc, ucas)
    toc = iostore.parse_toc(path)
    assert toc is not None
    assert toc.compression_methods == ["Oodle"]
    assert {tf.path for tf in toc.files} == set(_FILES)          # paths still recovered
    out = tmp_path / "out"
    assert iostore.extract(path, toc, out) == 0                  # Oodle blocks deferred
    assert not out.exists() or not any(out.rglob("*.*"))


def test_encrypted_extract_with_key(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    utoc, ucas = build_iostore(_FILES, compress="zlib", encrypt=True, aes_key=_AES_KEY)
    path = _write_pair(tmp_path, utoc, ucas)
    # no key: the directory index is opaque -> no paths, nothing extracted
    blind = iostore.parse_toc(path)
    assert blind is not None and blind.files == []
    assert iostore.extract(path, blind, tmp_path / "blind") == 0
    # with key: directory index decrypts + chunks decrypt + extract
    toc = iostore.parse_toc(path, aes_key=_AES_KEY)
    assert toc is not None
    assert {tf.path for tf in toc.files} == set(_FILES)
    out = tmp_path / "out"
    assert iostore.extract(path, toc, out, aes_key=_AES_KEY) == 2
    assert (out / "Content/data.json").read_bytes() == _FILES["Content/data.json"]


def test_extract_without_ucas_returns_zero(tmp_path: Path) -> None:
    utoc, _ucas = build_iostore(_FILES)            # write the .utoc but not the .ucas
    path = _write(tmp_path, utoc)
    toc = iostore.parse_toc(path)
    assert toc is not None
    assert iostore.extract(path, toc, tmp_path / "out") == 0
