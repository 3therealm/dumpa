"""UE5 IoStore `.utoc` header parser: enumerate-only, extraction deferred."""

from __future__ import annotations

from pathlib import Path

from _iostore_build import FLAG_COMPRESSED, FLAG_ENCRYPTED, FLAG_INDEXED, build_toc

from dumpa.core import iostore


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "global.utoc"
    p.write_bytes(data)
    return p


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
