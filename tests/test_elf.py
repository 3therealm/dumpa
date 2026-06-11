"""Tests for the zero-dep ELF parser (core.elf)."""

from __future__ import annotations

from pathlib import Path

from _elf_build import LOAD_VADDR_BASE, build_elf

from dumpa.core.elf import parse_elf


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "lib.so"
    p.write_bytes(data)
    return p


def test_parse_64bit(tmp_path: Path) -> None:
    data, _ = build_elf(bits=64, machine=0xB7,
                        exports=(("il2cpp_init", 0x10500, 32),), imports=("malloc",))
    elf = parse_elf(_write(tmp_path, data))
    assert elf is not None
    assert elf.bitness == "64-bit"
    assert elf.machine == "AArch64"
    names = {s.name for s in elf.sections}
    assert {".dynsym", ".dynstr", ".shstrtab"} <= names
    exports = {s.name: s for s in elf.exports}
    assert "il2cpp_init" in exports
    assert exports["il2cpp_init"].value == 0x10500
    assert exports["il2cpp_init"].size == 32
    assert {s.name for s in elf.imports} == {"malloc"}


def test_parse_32bit(tmp_path: Path) -> None:
    data, _ = build_elf(bits=32, machine=0x28,
                        exports=(("foo", 0x10200, 8),), imports=("free",))
    elf = parse_elf(_write(tmp_path, data))
    assert elf is not None
    assert elf.bitness == "32-bit"
    assert elf.machine == "ARM (32-bit)"
    assert {s.name for s in elf.exports} == {"foo"}
    assert {s.name for s in elf.imports} == {"free"}


def test_offset_to_rva(tmp_path: Path) -> None:
    data, payload_off = build_elf(payload=b"MARKER")
    elf = parse_elf(_write(tmp_path, data))
    assert elf is not None
    assert elf.offset_to_rva(payload_off) == LOAD_VADDR_BASE + payload_off
    assert elf.offset_to_rva(len(data) + 1000) is None


def test_stripped_has_no_symbols(tmp_path: Path) -> None:
    data, _ = build_elf(exports=(), imports=())
    elf = parse_elf(_write(tmp_path, data))
    assert elf is not None
    assert elf.exports == ()
    assert elf.imports == ()


def test_no_pt_load_maps_nothing(tmp_path: Path) -> None:
    data, payload_off = build_elf(payload=b"X", with_load=False)
    elf = parse_elf(_write(tmp_path, data))
    assert elf is not None
    assert elf.offset_to_rva(payload_off) is None


def test_section_at(tmp_path: Path) -> None:
    data, payload_off = build_elf(payload=b"\x90" * 64)
    elf = parse_elf(_write(tmp_path, data))
    assert elf is not None
    # An offset inside the payload lands in the allocated .text section.
    assert elf.section_at(payload_off) == ".text"
    assert elf.section_at(payload_off + 63) == ".text"
    # The ELF header region belongs to no allocated section.
    assert elf.section_at(0) is None
    # Past every section.
    assert elf.section_at(len(data) + 1000) is None


def test_symbol_at_rva(tmp_path: Path) -> None:
    data, _ = build_elf(exports=(("native_fn", 0x10500, 16),))
    elf = parse_elf(_write(tmp_path, data))
    assert elf is not None
    assert elf.symbol_at_rva(0x10500) == "native_fn"     # start of span
    assert elf.symbol_at_rva(0x1050F) == "native_fn"     # last covered byte
    assert elf.symbol_at_rva(0x10510) is None            # one past the end
    assert elf.symbol_at_rva(0x104FF) is None            # before the start


def test_symbol_at_rva_demangles_cpp(tmp_path: Path) -> None:
    data, _ = build_elf(exports=(("_ZN3Foo3Bar3bazEv", 0x10600, 8),))
    elf = parse_elf(_write(tmp_path, data))
    assert elf is not None
    assert elf.symbol_at_rva(0x10600) == "Foo::Bar::baz"


def test_truncated_returns_none(tmp_path: Path) -> None:
    data, _ = build_elf()
    assert parse_elf(_write(tmp_path, data[:30])) is None


def test_non_elf_returns_none(tmp_path: Path) -> None:
    assert parse_elf(_write(tmp_path, b"not an elf at all")) is None
