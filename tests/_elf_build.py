"""Hand-rolled ELF encoder for tests: build minimal valid shared-object bytes.

Not a product module — it lets the ELF-parser and native-scanner tests synthesize a
`.so` without shipping a real binary. Emits the subset the parser reads: ELF header,
one PT_LOAD segment (covering the whole file, so file offset N maps to vaddr
LOAD_VADDR_BASE + N), a `.dynsym` (+ `.dynstr`), and a `.shstrtab`.
"""

from __future__ import annotations

import struct

LOAD_VADDR_BASE = 0x10000


def build_elf(*, bits: int = 64, endian: str = "<", machine: int = 0xB7,
              exports: tuple[tuple[str, int, int], ...] = (("exported_fn", 0x10500, 16),),
              imports: tuple[str, ...] = ("imported_fn",),
              payload: bytes = b"", with_load: bool = True) -> tuple[bytes, int]:
    """Return (elf_bytes, payload_offset). exports are (name, st_value, st_size)."""
    is64 = bits == 64
    en = endian
    sym_size = 24 if is64 else 16
    sh_size = 64 if is64 else 40
    ph_size = 56 if is64 else 32
    eh_size = 64 if is64 else 52

    def pack_sym(name_off: int, value: int, size: int, info: int, shndx: int) -> bytes:
        if is64:
            return struct.pack(en + "IBBHQQ", name_off, info, 0, shndx, value, size)
        return struct.pack(en + "IIIBBH", name_off, value, size, info, 0, shndx)

    dynstr = bytearray(b"\x00")
    syms = [b"\x00" * sym_size]  # index 0: the mandatory null symbol
    for name, value, size in exports:
        off = len(dynstr)
        dynstr += name.encode("latin-1") + b"\x00"
        syms.append(pack_sym(off, value, size, (1 << 4) | 2, 1))   # GLOBAL FUNC, defined
    for name in imports:
        off = len(dynstr)
        dynstr += name.encode("latin-1") + b"\x00"
        syms.append(pack_sym(off, 0, 0, (1 << 4) | 0, 0))          # GLOBAL NOTYPE, undef
    dynsym = b"".join(syms)
    dynstr = bytes(dynstr)

    shstr = bytearray(b"\x00")

    def shname(s: str) -> int:
        off = len(shstr)
        shstr.extend(s.encode("latin-1") + b"\x00")
        return off

    n_dynsym, n_dynstr, n_shstr = shname(".dynsym"), shname(".dynstr"), shname(".shstrtab")
    shstr = bytes(shstr)

    # Layout: ehdr | phdr | payload | .dynsym | .dynstr | .shstrtab | pad | shdrs
    phoff = eh_size
    payload_off = phoff + ph_size
    dynsym_off = payload_off + len(payload)
    dynstr_off = dynsym_off + len(dynsym)
    shstr_off = dynstr_off + len(dynstr)
    raw_end = shstr_off + len(shstr)
    shoff = (raw_end + 7) & ~7
    pad = shoff - raw_end
    shnum = 4                      # NULL, .dynsym, .dynstr, .shstrtab
    total = shoff + shnum * sh_size

    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1 if en == "<" else 2, 1]) + b"\x00" * 9
    if is64:
        ehdr = ident + struct.pack(
            en + "HHIQQQIHHHHHH", 3, machine, 1, 0, phoff, shoff, 0,
            eh_size, ph_size, 1, sh_size, shnum, 3)
    else:
        ehdr = ident + struct.pack(
            en + "HHIIIIIHHHHHH", 3, machine, 1, 0, phoff, shoff, 0,
            eh_size, ph_size, 1, sh_size, shnum, 3)

    p_type = 1 if with_load else 0
    if is64:
        phdr = struct.pack(en + "IIQQQQQQ", p_type, 5, 0, LOAD_VADDR_BASE,
                           LOAD_VADDR_BASE, total, total, 0x1000)
    else:
        phdr = struct.pack(en + "IIIIIIII", p_type, 0, LOAD_VADDR_BASE,
                           LOAD_VADDR_BASE, total, total, 5, 0x1000)

    def shdr(name: int, typ: int, offset: int, size: int, link: int, entsize: int) -> bytes:
        if is64:
            return struct.pack(en + "IIQQQQIIQQ", name, typ, 0, 0, offset, size,
                               link, 0, 1, entsize)
        return struct.pack(en + "IIIIIIIIII", name, typ, 0, 0, offset, size,
                           link, 0, 1, entsize)

    shdrs = (
        shdr(0, 0, 0, 0, 0, 0)
        + shdr(n_dynsym, 11, dynsym_off, len(dynsym), 2, sym_size)   # link=2 (.dynstr)
        + shdr(n_dynstr, 3, dynstr_off, len(dynstr), 0, 0)
        + shdr(n_shstr, 3, shstr_off, len(shstr), 0, 0)
    )

    out = ehdr + phdr + payload + dynsym + dynstr + shstr + b"\x00" * pad + shdrs
    assert len(out) == total
    return out, payload_off
