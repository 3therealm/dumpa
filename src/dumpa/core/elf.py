"""Zero-dependency ELF parser for native shared objects (`lib/<abi>/*.so`).

Reads sections, symbols (`.dynsym` + `.symtab`), and `PT_LOAD` segments straight from
the binary with the stdlib alone (`struct`) — same no-extra-deps ethos as `core.axml`.
Parsing is seek-based: only the program-header table, the section-header table, and the
symbol/string tables are read, never the whole multi-hundred-MB library.

It powers two things: a per-library symbol/section inventory (the native-symbol scanner)
and file-offset -> RVA mapping, so a finding located by byte offset in a `.so` can also
report its virtual address. Any inconsistency raises `ElfError`, caught at the
`parse_elf` boundary so callers degrade to "no native facts", never crash.

References: ELF spec (Elf{32,64}_Ehdr / _Shdr / _Phdr / _Sym).
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from pathlib import Path

from dumpa.core.errors import ElfError

logger = logging.getLogger("dumpa")

_ELF_MAGIC = b"\x7fELF"
# e_machine -> readable architecture (shared with the lightweight header read in native.py).
_MACHINES = {
    0x28: "ARM (32-bit)",
    0xB7: "AArch64",
    0x03: "x86",
    0x3E: "x86-64",
    0xF3: "RISC-V",
}

# sh_type
_SHT_SYMTAB = 2
_SHT_DYNSYM = 11
# p_type
_PT_LOAD = 1
# symbol bind / section index
_STB_GLOBAL = 1
_STB_WEAK = 2
_SHN_UNDEF = 0

# Defensive caps so a pathological library cannot exhaust memory.
_MAX_SYMBOLS = 2_000_000
_MAX_STRTAB = 64 * 1024 * 1024


@dataclass(frozen=True)
class Section:
    """One ELF section header (only the fields we surface)."""
    name: str
    type: int
    addr: int          # sh_addr (virtual address; 0 when not allocated)
    offset: int        # sh_offset (file)
    size: int
    flags: int


@dataclass(frozen=True)
class Symbol:
    """One ELF symbol from `.dynsym`/`.symtab`."""
    name: str
    value: int         # st_value == RVA for defined symbols
    size: int
    bind: int          # st_info >> 4 (STB_*)
    type: int          # st_info & 0xf (STT_*)
    defined: bool      # st_shndx != SHN_UNDEF


@dataclass(frozen=True)
class ElfFile:
    """Parsed ELF metadata for one shared object."""
    bitness: str       # "32-bit" | "64-bit"
    machine: str
    sections: tuple[Section, ...]
    symbols: tuple[Symbol, ...]
    # PT_LOAD segments as (p_offset, p_vaddr, p_filesz), for offset -> RVA mapping.
    loads: tuple[tuple[int, int, int], ...]

    @property
    def exports(self) -> tuple[Symbol, ...]:
        """Defined GLOBAL/WEAK symbols — what this library provides."""
        return tuple(s for s in self.symbols
                     if s.defined and s.bind in (_STB_GLOBAL, _STB_WEAK))

    @property
    def imports(self) -> tuple[Symbol, ...]:
        """Undefined symbols — what this library needs from elsewhere."""
        return tuple(s for s in self.symbols if not s.defined)

    def offset_to_rva(self, offset: int) -> int | None:
        """Map a file offset to a virtual address via the covering PT_LOAD, or None."""
        for p_offset, p_vaddr, p_filesz in self.loads:
            if p_offset <= offset < p_offset + p_filesz:
                return p_vaddr + (offset - p_offset)
        return None


def _read_at(f, offset: int, size: int) -> bytes:
    f.seek(offset)
    blob = f.read(size)
    if len(blob) != size:
        raise ElfError(f"truncated read: wanted {size} bytes at {offset}, got {len(blob)}")
    return blob


def _cstr(blob: bytes, offset: int) -> str:
    """Read a NUL-terminated string from a string table; '' when out of range/empty."""
    if not (0 <= offset < len(blob)):
        return ""
    end = blob.find(b"\x00", offset)
    raw = blob[offset:] if end < 0 else blob[offset:end]
    return raw.decode("latin-1")


def parse_elf(path: Path) -> ElfFile | None:
    """Parse an ELF shared object. Returns None on any non-ELF/malformed/truncated input."""
    try:
        with path.open("rb") as f:
            return _parse(f)
    except (ElfError, OSError, struct.error):
        logger.debug("ELF parse failed for %s", path, exc_info=True)
        return None


def _parse(f) -> ElfFile:
    head = f.read(64)
    if len(head) < 52 or head[:4] != _ELF_MAGIC:
        raise ElfError("not an ELF file")
    ei_class, ei_data = head[4], head[5]
    if ei_class == 1:
        is64, bitness = False, "32-bit"
    elif ei_class == 2:
        is64, bitness = True, "64-bit"
    else:
        raise ElfError(f"bad EI_CLASS {ei_class}")
    if ei_data == 1:
        en = "<"
    elif ei_data == 2:
        en = ">"
    else:
        raise ElfError(f"bad EI_DATA {ei_data}")

    (e_machine,) = struct.unpack_from(en + "H", head, 18)
    if is64:
        (e_phoff,) = struct.unpack_from(en + "Q", head, 32)
        (e_shoff,) = struct.unpack_from(en + "Q", head, 40)
        e_phentsize, e_phnum = struct.unpack_from(en + "HH", head, 54)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(en + "HHH", head, 58)
    else:
        (e_phoff,) = struct.unpack_from(en + "I", head, 28)
        (e_shoff,) = struct.unpack_from(en + "I", head, 32)
        e_phentsize, e_phnum = struct.unpack_from(en + "HH", head, 42)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(en + "HHH", head, 46)

    machine = _MACHINES.get(e_machine, f"machine 0x{e_machine:x}")
    loads = _parse_program_headers(f, en, is64, e_phoff, e_phentsize, e_phnum)
    raw = _parse_section_headers(f, en, is64, e_shoff, e_shentsize, e_shnum)
    sections = _resolve_sections(f, raw, e_shstrndx)
    symbols = _parse_symbols(f, en, is64, raw)
    return ElfFile(bitness=bitness, machine=machine, sections=sections,
                   symbols=symbols, loads=loads)


def _parse_program_headers(f, en: str, is64: bool, phoff: int, entsize: int,
                           num: int) -> tuple[tuple[int, int, int], ...]:
    if not (phoff and num):
        return ()
    table = _read_at(f, phoff, num * entsize)
    loads: list[tuple[int, int, int]] = []
    for i in range(num):
        ent = table[i * entsize:(i + 1) * entsize]
        if is64:
            (p_type,) = struct.unpack_from(en + "I", ent, 0)
            p_offset, p_vaddr = struct.unpack_from(en + "QQ", ent, 8)
            (p_filesz,) = struct.unpack_from(en + "Q", ent, 32)
        else:
            p_type, p_offset, p_vaddr = struct.unpack_from(en + "III", ent, 0)
            (p_filesz,) = struct.unpack_from(en + "I", ent, 16)
        if p_type == _PT_LOAD:
            loads.append((p_offset, p_vaddr, p_filesz))
    return tuple(loads)


# Raw section header: (name_off, type, flags, addr, offset, size, link, entsize).
_RawSection = tuple[int, int, int, int, int, int, int, int]


def _parse_section_headers(f, en: str, is64: bool, shoff: int, entsize: int,
                           num: int) -> list[_RawSection]:
    if not (shoff and num):
        return []
    table = _read_at(f, shoff, num * entsize)
    out: list[_RawSection] = []
    for i in range(num):
        ent = table[i * entsize:(i + 1) * entsize]
        if is64:
            sh_name, sh_type = struct.unpack_from(en + "II", ent, 0)
            sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(en + "QQQQ", ent, 8)
            sh_link, _ = struct.unpack_from(en + "II", ent, 40)
            (sh_entsize,) = struct.unpack_from(en + "Q", ent, 56)
        else:
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, _, _, sh_entsize) = struct.unpack_from(en + "IIIIIIIIII", ent, 0)
        out.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                    sh_link, sh_entsize))
    return out


def _read_strtab(f, raw: list[_RawSection], index: int) -> bytes:
    if not (0 <= index < len(raw)):
        return b""
    _, _, _, _, offset, size, _, _ = raw[index]
    size = min(size, _MAX_STRTAB)
    return _read_at(f, offset, size) if size else b""


def _resolve_sections(f, raw: list[_RawSection], shstrndx: int) -> tuple[Section, ...]:
    names = _read_strtab(f, raw, shstrndx)
    return tuple(
        Section(name=_cstr(names, r[0]), type=r[1], addr=r[3],
                offset=r[4], size=r[5], flags=r[2])
        for r in raw
    )


def _parse_symbols(f, en: str, is64: bool, raw: list[_RawSection]) -> tuple[Symbol, ...]:
    entry_size = 24 if is64 else 16
    symbols: list[Symbol] = []
    for _, sh_type, _, _, sh_offset, sh_size, sh_link, sh_entsize in raw:
        if sh_type not in (_SHT_SYMTAB, _SHT_DYNSYM) or sh_size == 0:
            continue
        es = sh_entsize or entry_size
        count = sh_size // es
        if count > _MAX_SYMBOLS:
            logger.debug("capping symbol table at %d (had %d)", _MAX_SYMBOLS, count)
            count = _MAX_SYMBOLS
        strtab = _read_strtab(f, raw, sh_link)
        blob = _read_at(f, sh_offset, count * es)
        for i in range(count):
            ent = blob[i * es:(i + 1) * es]
            if is64:
                (st_name,) = struct.unpack_from(en + "I", ent, 0)
                st_info = ent[4]
                (st_shndx,) = struct.unpack_from(en + "H", ent, 6)
                st_value, st_size = struct.unpack_from(en + "QQ", ent, 8)
            else:
                st_name, st_value, st_size = struct.unpack_from(en + "III", ent, 0)
                st_info = ent[12]
                (st_shndx,) = struct.unpack_from(en + "H", ent, 14)
            name = _cstr(strtab, st_name)
            if not name:          # skip the null symbol and unnamed entries
                continue
            symbols.append(Symbol(
                name=name, value=st_value, size=st_size,
                bind=st_info >> 4, type=st_info & 0xF, defined=st_shndx != _SHN_UNDEF,
            ))
    return tuple(symbols)
