"""Zero-dependency structural DEX parser for `classesN.dex`.

Reads the DEX header and the string / type / field / method / class_def pools straight
from the binary with the stdlib alone (`struct`) — same no-extra-deps ethos as `core.elf`
and `core.axml`. It is *almost* structural-only: it reads `code_item` headers to size each
method's byte span; decodes the two `const-string` instructions (0x1a / 0x1b) to build a
string-constant cross-reference; decodes each class's `static_values` encoded_array to tie
a string constant to the static field it initializes; and, on demand, walks a single
method's bytecode to name the instruction (and accessed field) covering a given offset.
Every other opcode is advanced past by width alone; their operands are never interpreted.

It powers these: a per-file class/method/field inventory (the `dex` scanner); a
file-offset -> (class, method) map (`DexFile.locate`), so a finding located by byte offset
inside a `.dex` — e.g. a tracker class-path string a content scanner matched — can report
the owning class (and method, when the offset lands in bytecode); a string-constant xref
(`DexFile.locate_string_xref`), so an offset inside an *arbitrary* string constant — a
hardcoded secret, endpoint URL, or tracker domain — resolves to the method(s) whose
`const-string` loads it; a static-field xref (`DexFile.locate_field_init`), resolving the
same string offset to the static field(s) it initializes; and instruction-level refinement
(`DexFile.locate_instruction`), mapping a code-item offset to its instruction's bytecode
offset, opcode, and accessed field (for `iget*`/`iput*`/`sget*`/`sput*`).

What `locate` resolves:
  * offset inside a `code_item`     -> (owning class, method)        — exact
  * offset inside a class descriptor string -> (the class it names, None)

What `locate_string_xref` adds:
  * offset inside any string_data range -> the methods that `const-string`-load it

What `locate_field_init` adds:
  * offset inside any string_data range -> the static field(s) it initializes

What `locate_instruction` adds:
  * offset inside a `code_item` -> (bytecode unit offset, opcode, accessed field|None)

The const-string walker advances by an opcode-width table and skips the three inline
payload pseudo-instructions whole (so payload bytes are never misread as a `const-string`);
it bails out of a method on any truncation / unused opcode / overrunning payload, keeping
what it found. Any inconsistency raises `DexError`, caught at the `parse_dex` boundary so
callers degrade to "no DEX facts", never crash.

References: Android DEX format (header_item / string_data_item / type_id_item /
field_id_item / method_id_item / class_def_item / class_data_item / code_item).
"""

from __future__ import annotations

import bisect
import logging
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from dumpa.core.errors import DexError

logger = logging.getLogger("dumpa")

_DEX_MAGIC = b"dex\n"
_ENDIAN_CONSTANT = 0x12345678
_REVERSE_ENDIAN_CONSTANT = 0x78563412
_NO_INDEX = 0xFFFFFFFF
_HEADER_SIZE = 0x70
_CODE_ITEM_HEADER = 16          # bytes before insns[] in a code_item

# Defensive caps so a pathological file cannot exhaust memory / time.
_MAX_STRINGS = 4_000_000
_MAX_CLASSES = 500_000
_MAX_METHODS = 4_000_000        # total code-spans built across all classes
_MAX_STR_BLOB = 96 * 1024 * 1024
_MAX_CLASS_DATA = 256 * 1024    # per-class_data_item read window
_MAX_INSNS_UNITS = 16 * 1024 * 1024


@dataclass(frozen=True)
class DexClass:
    """One class_def's identity and member names (no bytecode)."""
    descriptor: str                  # raw DEX type descriptor, "Lcom/foo/Bar;"
    name: str                        # dotted, "com.foo.Bar"
    superclass: str | None           # dotted, None when absent (NO_INDEX)
    method_names: tuple[str, ...]
    field_names: tuple[str, ...]


@dataclass(frozen=True)
class InstructionHit:
    """One instruction located inside a method's bytecode by `DexFile.locate_instruction`."""
    bytecode_offset: int             # instruction offset from method start, in 16-bit units
    opcode: int                      # the Dalvik opcode byte (-1 for an inline payload)
    field: str | None                # "Class.name" for a field-access op, else None


@dataclass(frozen=True)
class DexFile:
    """Parsed structural metadata for one .dex."""
    version: int                     # 35..41 from "dex\n0NN\0"
    classes: tuple[DexClass, ...]
    # Sorted, non-overlapping spans for offset -> owner resolution.
    code_spans: tuple[tuple[int, int, str, str], ...]   # (start, end, class, method)
    desc_spans: tuple[tuple[int, int, str], ...]        # (start, end, dotted class)
    # Sorted spans over string_data of const-string-referenced strings.
    xref_spans: tuple[tuple[int, int, tuple[tuple[str, str], ...]], ...] = ()
    # Sorted spans over string_data of strings that initialize a static field.
    field_init_spans: tuple[tuple[int, int, tuple[str, ...]], ...] = ()
    # field_idx -> "DefiningClass.name", for resolving field-access instruction operands.
    field_descriptors: tuple[str, ...] = ()

    def _code_span_at(self, offset: int) -> tuple[int, int, str, str] | None:
        starts = [s[0] for s in self.code_spans]
        i = bisect.bisect_right(starts, offset) - 1
        if 0 <= i < len(self.code_spans):
            span = self.code_spans[i]
            if span[0] <= offset < span[1]:
                return span
        return None

    def locate(self, offset: int) -> tuple[str, str | None] | None:
        """Map a file byte offset to (dotted_class, method_name|None), or None.

        A code-item hit yields class + method; a class-descriptor-string hit yields the
        class the string names (method None). Anything else is None.
        """
        span = self._code_span_at(offset)
        if span is not None:
            return (span[2], span[3])
        dstarts = [s[0] for s in self.desc_spans]
        j = bisect.bisect_right(dstarts, offset) - 1
        if 0 <= j < len(self.desc_spans):
            start, end, cls = self.desc_spans[j]
            if start <= offset < end:
                return (cls, None)
        return None

    def locate_string_xref(self, offset: int) -> tuple[tuple[str, str], ...]:
        """Methods that `const-string`-load the string whose string_data range covers
        `offset`. Empty when the offset is in no referenced string. Each entry is a
        (dotted_class, method) pair; multiple entries mean the string is loaded in more
        than one place."""
        starts = [s[0] for s in self.xref_spans]
        i = bisect.bisect_right(starts, offset) - 1
        if 0 <= i < len(self.xref_spans):
            start, end, refs = self.xref_spans[i]
            if start <= offset < end:
                return refs
        return ()

    def locate_field_init(self, offset: int) -> tuple[str, ...]:
        """Static field(s) whose `static_values` initializer is the string whose
        string_data range covers `offset`. Empty when the offset initializes no static
        field. Each entry is a "DefiningClass.name" descriptor; multiple entries mean the
        same string constant initializes more than one static field."""
        starts = [s[0] for s in self.field_init_spans]
        i = bisect.bisect_right(starts, offset) - 1
        if 0 <= i < len(self.field_init_spans):
            start, end, fields = self.field_init_spans[i]
            if start <= offset < end:
                return fields
        return ()

    def locate_instruction(self, path: Path, offset: int) -> InstructionHit | None:
        """Refine a code-item `offset` to the instruction covering it. Reads only the one
        covering method's bytecode from `path`. Returns the instruction's bytecode offset
        (in 16-bit units from method start), its opcode, and — for a field-access op
        (`iget*`/`iput*`/`sget*`/`sput*`) — the accessed field. None when `offset` is in no
        code item, lands in a code_item header, or the method can't be read."""
        span = self._code_span_at(offset)
        if span is None:
            return None
        start, end, _cls, _meth = span
        insns_start = start + _CODE_ITEM_HEADER
        if offset < insns_start:
            return None                  # inside the code_item header, not the bytecode
        try:
            with path.open("rb") as f:
                f.seek(insns_start)
                insns = f.read(end - insns_start)
        except OSError:
            return None
        hit = _instruction_at(insns, offset - insns_start)
        if hit is None:
            return None
        unit_off, opcode, field_idx = hit
        field = (self.field_descriptors[field_idx]
                 if field_idx is not None and 0 <= field_idx < len(self.field_descriptors)
                 else None)
        return InstructionHit(bytecode_offset=unit_off, opcode=opcode, field=field)


def parse_dex(path: Path) -> DexFile | None:
    """Parse a .dex. Returns None on any non-DEX/malformed/truncated input."""
    try:
        with path.open("rb") as f:
            return _parse(f)
    except (DexError, OSError, struct.error):
        logger.debug("DEX parse failed for %s", path, exc_info=True)
        return None


def _descriptor_to_dotted(descriptor: str) -> str:
    """`Lcom/foo/Bar;` -> `com.foo.Bar`; primitives/arrays pass through unchanged."""
    if len(descriptor) >= 2 and descriptor[0] == "L" and descriptor[-1] == ";":
        return descriptor[1:-1].replace("/", ".")
    return descriptor


def _is_class_descriptor(value: str) -> bool:
    return len(value) >= 2 and value[0] == "L" and value[-1] == ";"


def _read_at(f: BinaryIO, offset: int, size: int) -> bytes:
    f.seek(offset)
    blob = f.read(size)
    if len(blob) != size:
        raise DexError(f"truncated read: wanted {size} bytes at {offset}, got {len(blob)}")
    return blob


def _uleb128(buf: bytes, pos: int) -> tuple[int, int]:
    """Read an unsigned LEB128 at pos; return (value, next_pos). Bounded to 5 bytes."""
    result = 0
    for shift in range(0, 35, 7):
        if pos >= len(buf):
            raise DexError("uleb128 out of range")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
    raise DexError("uleb128 too long")


# --- const-string cross-reference -------------------------------------------------------
#
# To find `const-string`/`const-string/jumbo` ops we only need to *advance* across every
# other instruction, so a width table (in 16-bit code units) suffices — operands are never
# interpreted. Width 0 marks an unused/invalid opcode: hitting one means the cursor is lost,
# so the walker bails. The three inline payload pseudo-instructions are not opcodes (their
# first code unit is 0x01xx/0x02xx/0x03xx) and are sized by formula, not this table.

_CONST_STRING = 0x1A            # 21c, 2 units: string idx = u16 at +1
_CONST_STRING_JUMBO = 0x1B      # 31c, 3 units: string idx = u32 at +1
_PACKED_SWITCH_PAYLOAD = 0x0100
_SPARSE_SWITCH_PAYLOAD = 0x0200
_FILL_ARRAY_DATA_PAYLOAD = 0x0300

# Field-access opcodes: iget*/iput* (0x52..0x5F, format 22c) and sget*/sput*
# (0x60..0x6D, format 21c). All carry field_idx as the u16 at code-unit +1.
_FIELD_OP_LO = 0x52
_FIELD_OP_HI = 0x6D

# encoded_value types we must distinguish to walk a static_values encoded_array: a string
# initializer (the one we record), the two zero-payload values, and the two nested
# aggregates we cannot size cheaply (bail there). Every other scalar is (value_arg+1) bytes.
_VALUE_STRING = 0x17
_VALUE_ARRAY = 0x1C
_VALUE_ANNOTATION = 0x1D
_VALUE_NULL = 0x1E
_VALUE_BOOLEAN = 0x1F


def _build_opcode_widths() -> bytes:
    w = bytearray(256)          # default 0 = unused/invalid -> bail

    def span(lo: int, hi: int, units: int) -> None:
        for op in range(lo, hi + 1):
            w[op] = units

    span(0x00, 0x01, 1)         # nop, move
    span(0x02, 0x02, 2)         # move/from16
    span(0x03, 0x03, 3)         # move/16
    span(0x04, 0x04, 1)         # move-wide
    span(0x05, 0x05, 2)         # move-wide/from16
    span(0x06, 0x06, 3)         # move-wide/16
    span(0x07, 0x07, 1)         # move-object
    span(0x08, 0x08, 2)         # move-object/from16
    span(0x09, 0x09, 3)         # move-object/16
    span(0x0A, 0x11, 1)         # move-result*/exception, return*
    span(0x12, 0x12, 1)         # const/4
    span(0x13, 0x13, 2)         # const/16
    span(0x14, 0x14, 3)         # const
    span(0x15, 0x16, 2)         # const/high16, const-wide/16
    span(0x17, 0x17, 3)         # const-wide/32
    span(0x18, 0x18, 5)         # const-wide
    span(0x19, 0x19, 2)         # const-wide/high16
    span(0x1A, 0x1A, 2)         # const-string
    span(0x1B, 0x1B, 3)         # const-string/jumbo
    span(0x1C, 0x1C, 2)         # const-class
    span(0x1D, 0x1E, 1)         # monitor-enter/exit
    span(0x1F, 0x20, 2)         # check-cast, instance-of
    span(0x21, 0x21, 1)         # array-length
    span(0x22, 0x23, 2)         # new-instance, new-array
    span(0x24, 0x26, 3)         # filled-new-array[/range], fill-array-data
    span(0x27, 0x28, 1)         # throw, goto
    span(0x29, 0x29, 2)         # goto/16
    span(0x2A, 0x2C, 3)         # goto/32, packed/sparse-switch
    span(0x2D, 0x31, 2)         # cmp*
    span(0x32, 0x3D, 2)         # if-* / if-*z
    # 0x3E..0x43 unused -> 0
    span(0x44, 0x51, 2)         # aget*/aput*
    span(0x52, 0x5F, 2)         # iget*/iput*
    span(0x60, 0x6D, 2)         # sget*/sput*
    span(0x6E, 0x72, 3)         # invoke-*
    # 0x73 unused -> 0
    span(0x74, 0x78, 3)         # invoke-*/range
    # 0x79..0x7A unused -> 0
    span(0x7B, 0x8F, 1)         # unary ops
    span(0x90, 0xAF, 2)         # binop
    span(0xB0, 0xCF, 1)         # binop/2addr
    span(0xD0, 0xD7, 2)         # binop/lit16
    span(0xD8, 0xE2, 2)         # binop/lit8
    # 0xE3..0xF9 unused -> 0
    span(0xFA, 0xFB, 4)         # invoke-polymorphic[/range]
    span(0xFC, 0xFD, 3)         # invoke-custom[/range]
    span(0xFE, 0xFF, 2)         # const-method-handle, const-method-type
    return bytes(w)


_OPCODE_WIDTHS = _build_opcode_widths()


def _u16(insns: bytes, unit: int) -> int:
    return insns[unit * 2] | (insns[unit * 2 + 1] << 8)


def _scan_const_strings(insns: bytes, nstrings: int) -> list[int]:
    """Walk one method's insns[] and return the string-pool indices its const-string ops
    load. Forward-only and bounded; bails (keeping what it found) on truncation, an unused
    opcode, or an overrunning payload — never raises. Payloads are skipped whole so their
    arbitrary bytes are never misread as a const-string."""
    out: list[int] = []
    n = len(insns) // 2
    i = 0
    while i < n:
        unit = _u16(insns, i)
        if unit == _PACKED_SWITCH_PAYLOAD:
            if i + 2 > n:
                break
            width = _u16(insns, i + 1) * 2 + 4
        elif unit == _SPARSE_SWITCH_PAYLOAD:
            if i + 2 > n:
                break
            width = _u16(insns, i + 1) * 4 + 2
        elif unit == _FILL_ARRAY_DATA_PAYLOAD:
            if i + 4 > n:
                break
            element_width = _u16(insns, i + 1)
            size = _u16(insns, i + 2) | (_u16(insns, i + 3) << 16)
            width = (size * element_width + 1) // 2 + 4
        else:
            op = unit & 0xFF
            width = _OPCODE_WIDTHS[op]
            if width == 0:
                break
            if op == _CONST_STRING and i + 2 <= n:
                idx = _u16(insns, i + 1)
                if 0 <= idx < nstrings:
                    out.append(idx)
            elif op == _CONST_STRING_JUMBO and i + 3 <= n:
                idx = _u16(insns, i + 1) | (_u16(insns, i + 2) << 16)
                if 0 <= idx < nstrings:
                    out.append(idx)
        if i + width > n:
            break
        i += width
    return out


def _instruction_at(insns: bytes, rel_byte: int) -> tuple[int, int, int | None] | None:
    """Walk insns[] and return (unit_offset, opcode, field_idx|None) of the instruction
    whose byte span covers `rel_byte` (a byte offset from the start of insns[]), or None.

    Same width-table / payload-sizing / bail rules as `_scan_const_strings`: a lost cursor
    (truncation, unused opcode, overrunning payload) stops the walk and yields None rather
    than a misaligned guess. An inline payload reports opcode -1 and no field."""
    n = len(insns) // 2
    if rel_byte < 0:
        return None
    i = 0
    while i < n:
        unit = _u16(insns, i)
        opcode: int | None = None
        if unit == _PACKED_SWITCH_PAYLOAD:
            if i + 2 > n:
                break
            width = _u16(insns, i + 1) * 2 + 4
        elif unit == _SPARSE_SWITCH_PAYLOAD:
            if i + 2 > n:
                break
            width = _u16(insns, i + 1) * 4 + 2
        elif unit == _FILL_ARRAY_DATA_PAYLOAD:
            if i + 4 > n:
                break
            element_width = _u16(insns, i + 1)
            size = _u16(insns, i + 2) | (_u16(insns, i + 3) << 16)
            width = (size * element_width + 1) // 2 + 4
        else:
            opcode = unit & 0xFF
            width = _OPCODE_WIDTHS[opcode]
            if width == 0:
                break
        if i + width > n:
            break
        if i * 2 <= rel_byte < (i + width) * 2:
            if opcode is None:
                return (i, -1, None)        # inside an inline payload
            field_idx = None
            if _FIELD_OP_LO <= opcode <= _FIELD_OP_HI and i + 2 <= n:
                field_idx = _u16(insns, i + 1)
            return (i, opcode, field_idx)
        i += width
    return None


def _build_xref_spans(
    f: BinaryIO,
    code_spans: list[tuple[int, int, str, str]],
    str_content: list[tuple[int, int]],
    nstrings: int,
) -> tuple[tuple[int, int, tuple[tuple[str, str], ...]], ...]:
    """Second pass over method code: map each const-string-referenced string index to the
    (class, method) loaders, then to its string_data byte range. Only referenced strings
    get a span, so memory tracks code references, not the whole string pool."""
    refs: dict[int, set[tuple[str, str]]] = {}
    for start, end, cls, meth in code_spans:
        insns_start = start + _CODE_ITEM_HEADER
        length = end - insns_start
        if length <= 0:
            continue
        try:
            f.seek(insns_start)
            insns = f.read(length)
        except OSError:
            continue
        for idx in _scan_const_strings(insns, nstrings):
            refs.setdefault(idx, set()).add((cls, meth))

    spans: list[tuple[int, int, tuple[tuple[str, str], ...]]] = []
    for idx, methods in refs.items():
        if not (0 <= idx < len(str_content)):
            continue
        cstart, cend = str_content[idx]
        if cend > cstart:
            spans.append((cstart, cend, tuple(sorted(methods))))
    spans.sort(key=lambda s: s[0])
    return tuple(spans)


def _decode_static_value_strings(f: BinaryIO, off: int, file_size: int,
                                 count: int) -> list[tuple[int, int]]:
    """Decode a class's `static_values` encoded_array, returning (element_index, string_idx)
    for each VALUE_STRING in the first `count` elements (element k initializes static field
    k). Scalars are skipped by their (value_arg+1) payload; a nested VALUE_ARRAY /
    VALUE_ANNOTATION can't be sized cheaply, so the walk stops there (keeping earlier
    strings) rather than misaligning later elements onto the wrong fields."""
    window = min(_MAX_CLASS_DATA, max(file_size - off, 0))
    if window <= 0:
        return []
    f.seek(off)
    buf = f.read(window)
    try:
        size, pos = _uleb128(buf, 0)
    except DexError:
        return []
    out: list[tuple[int, int]] = []
    for k in range(min(size, count)):
        if pos >= len(buf):
            break
        header = buf[pos]
        pos += 1
        vtype = header & 0x1F
        varg = header >> 5
        if vtype == _VALUE_STRING:
            nbytes = varg + 1
            if pos + nbytes > len(buf):
                break
            out.append((k, int.from_bytes(buf[pos:pos + nbytes], "little")))
            pos += nbytes
        elif vtype in (_VALUE_NULL, _VALUE_BOOLEAN):
            pass                              # value carried in value_arg; no payload
        elif vtype in (_VALUE_ARRAY, _VALUE_ANNOTATION):
            break                             # nested aggregate: stop before misaligning
        else:
            pos += varg + 1                   # every other scalar: (value_arg + 1) bytes
    return out


def _build_field_init_spans(
    f: BinaryIO,
    classes_static: list[tuple[list[int], int]],
    field_descriptors: tuple[str, ...],
    str_content: list[tuple[int, int]],
    file_size: int,
) -> tuple[tuple[int, int, tuple[str, ...]], ...]:
    """Map each string constant that initializes a static field to its string_data range and
    the field descriptor(s) it initializes. `classes_static` is (ordered static field_idxs,
    static_values_off) per class with an initializer array."""
    refs: dict[int, set[str]] = {}
    for static_idxs, sv_off in classes_static:
        for k, str_idx in _decode_static_value_strings(f, sv_off, file_size, len(static_idxs)):
            fidx = static_idxs[k]
            if 0 <= fidx < len(field_descriptors):
                refs.setdefault(str_idx, set()).add(field_descriptors[fidx])

    spans: list[tuple[int, int, tuple[str, ...]]] = []
    for idx, fields in refs.items():
        if not (0 <= idx < len(str_content)):
            continue
        cstart, cend = str_content[idx]
        if cend > cstart:
            spans.append((cstart, cend, tuple(sorted(fields))))
    spans.sort(key=lambda s: s[0])
    return tuple(spans)


def _read_field_descriptors(f: BinaryIO, en: str, off: int, size: int,
                            type_desc: list[int], strings: list[str]) -> tuple[str, ...]:
    """field_idx -> "DefiningClass.name". field_id_item is 8 bytes: class_idx (u16),
    type_idx (u16), name_idx (u32)."""
    if size == 0:
        return ()
    table = _read_at(f, off, size * 8)
    out: list[str] = []
    for i in range(size):
        class_idx, _type_idx, name_idx = struct.unpack_from(en + "HHI", table, i * 8)
        cls = ""
        if 0 <= class_idx < len(type_desc):
            s = type_desc[class_idx]
            if 0 <= s < len(strings):
                cls = _descriptor_to_dotted(strings[s])
        name = strings[name_idx] if 0 <= name_idx < len(strings) else ""
        out.append(f"{cls}.{name}" if cls else name)
    return tuple(out)


def _parse(f: BinaryIO) -> DexFile:
    head = f.read(_HEADER_SIZE)
    if len(head) < _HEADER_SIZE or head[:4] != _DEX_MAGIC:
        raise DexError("not a dex file")
    version = _parse_version(head[4:8])
    (endian_tag,) = struct.unpack_from("<I", head, 0x28)
    if endian_tag == _ENDIAN_CONSTANT:
        en = "<"
    elif endian_tag == _REVERSE_ENDIAN_CONSTANT:
        en = ">"
    else:
        raise DexError(f"bad endian tag 0x{endian_tag:08x}")

    string_ids_size, string_ids_off = struct.unpack_from(en + "II", head, 0x38)
    type_ids_size, type_ids_off = struct.unpack_from(en + "II", head, 0x40)
    field_ids_size, field_ids_off = struct.unpack_from(en + "II", head, 0x50)
    method_ids_size, method_ids_off = struct.unpack_from(en + "II", head, 0x58)
    class_defs_size, class_defs_off = struct.unpack_from(en + "II", head, 0x60)

    f.seek(0, 2)
    file_size = f.tell()

    strings, str_content = _read_strings(f, en, string_ids_off, string_ids_size, file_size)
    type_desc = _read_type_ids(f, en, type_ids_off, type_ids_size)
    field_names = _read_member_names(f, en, field_ids_off, field_ids_size, strings)
    field_descriptors = _read_field_descriptors(f, en, field_ids_off, field_ids_size,
                                                type_desc, strings)
    method_names = _read_member_names(f, en, method_ids_off, method_ids_size, strings)

    classes, code_spans, classes_static = _read_classes(
        f, en, class_defs_off, class_defs_size, file_size,
        strings, type_desc, field_names, method_names,
    )
    desc_spans = _build_desc_spans(type_desc, strings, str_content)
    code_spans.sort(key=lambda s: s[0])
    # const-string operands and encoded_value string indices are little-endian; skip the
    # xrefs on the (essentially theoretical) reverse-endian dex rather than misread them
    # into bogus attributions.
    if en == "<":
        xref_spans = _build_xref_spans(f, code_spans, str_content, len(strings))
        field_init_spans = _build_field_init_spans(
            f, classes_static, field_descriptors, str_content, file_size)
    else:
        xref_spans = ()
        field_init_spans = ()
    return DexFile(version=version, classes=tuple(classes),
                   code_spans=tuple(code_spans), desc_spans=tuple(desc_spans),
                   xref_spans=xref_spans, field_init_spans=field_init_spans,
                   field_descriptors=field_descriptors)


def _parse_version(raw: bytes) -> int:
    digits = raw[:3]
    if not digits.isdigit():
        raise DexError(f"bad dex version {raw!r}")
    return int(digits)


def _read_strings(f: BinaryIO, en: str, off: int, size: int,
                  file_size: int) -> tuple[list[str], list[tuple[int, int]]]:
    """Return (string values by index, (content_start, content_end) by index).

    The string_data items are read in one bounded contiguous blob (min..max offset +
    tail) rather than one seek per string. content_start/end are absolute file offsets of
    the MUTF-8 bytes (after the uleb length, before the NUL).
    """
    if size == 0:
        return [], []
    if size > _MAX_STRINGS:
        raise DexError(f"absurd string_ids_size {size}")
    id_table = _read_at(f, off, size * 4)
    offsets = struct.unpack(en + "I" * size, id_table)
    lo, hi = min(offsets), max(offsets)
    span = min(hi - lo + 65536, _MAX_STR_BLOB, max(file_size - lo, 0))
    blob = _read_at(f, lo, span)

    strings: list[str] = []
    content: list[tuple[int, int]] = []
    for o in offsets:
        rel = o - lo
        if not (0 <= rel < len(blob)):
            strings.append("")
            content.append((0, 0))
            continue
        _utf16_len, data_rel = _uleb128(blob, rel)
        end_rel = blob.find(b"\x00", data_rel)
        if end_rel < 0:
            end_rel = len(blob)
        raw = blob[data_rel:end_rel]
        strings.append(_mutf8(raw))
        content.append((lo + data_rel, lo + end_rel))
    return strings, content


def _mutf8(raw: bytes) -> str:
    """Decode Modified UTF-8 tolerantly. Class paths are ASCII, so this rarely matters;
    the embedded-NUL form (C0 80) is normalized and anything invalid falls back."""
    try:
        return raw.replace(b"\xc0\x80", b"\x00").decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _read_type_ids(f: BinaryIO, en: str, off: int, size: int) -> list[int]:
    """type_idx -> descriptor string index."""
    if size == 0:
        return []
    table = _read_at(f, off, size * 4)
    return list(struct.unpack(en + "I" * size, table))


def _read_member_names(f: BinaryIO, en: str, off: int, size: int, strings: list[str]) -> list[str]:
    """field_id/method_id index -> member name. Both items are 8 bytes with name_idx at +4."""
    if size == 0:
        return []
    table = _read_at(f, off, size * 8)
    names: list[str] = []
    for i in range(size):
        (name_idx,) = struct.unpack_from(en + "I", table, i * 8 + 4)
        names.append(strings[name_idx] if 0 <= name_idx < len(strings) else "")
    return names


def _build_desc_spans(type_desc: list[int], strings: list[str],
                      str_content: list[tuple[int, int]]) -> list[tuple[int, int, str]]:
    """Sorted (start, end, dotted) spans for every type descriptor that names a class."""
    spans: list[tuple[int, int, str]] = []
    for str_idx in type_desc:
        if not (0 <= str_idx < len(strings)):
            continue
        value = strings[str_idx]
        if not _is_class_descriptor(value):
            continue
        start, end = str_content[str_idx]
        if end > start:
            spans.append((start, end, _descriptor_to_dotted(value)))
    spans.sort(key=lambda s: s[0])
    return spans


def _read_classes(f: BinaryIO, en: str, off: int, size: int, file_size: int,
                  strings: list[str], type_desc: list[int],
                  field_names: list[str], method_names: list[str],
                  ) -> tuple[list[DexClass], list[tuple[int, int, str, str]],
                             list[tuple[list[int], int]]]:
    if size == 0:
        return [], [], []
    if size > _MAX_CLASSES:
        raise DexError(f"absurd class_defs_size {size}")
    table = _read_at(f, off, size * 32)

    def descriptor_for(type_idx: int) -> str:
        if 0 <= type_idx < len(type_desc):
            s = type_desc[type_idx]
            if 0 <= s < len(strings):
                return strings[s]
        return ""

    classes: list[DexClass] = []
    code_spans: list[tuple[int, int, str, str]] = []
    classes_static: list[tuple[list[int], int]] = []
    for i in range(size):
        (class_idx, _access, super_idx, _ifaces, _src, _ann,
         class_data_off, static_values_off) = struct.unpack_from(en + "IIIIIIII", table, i * 32)
        descriptor = descriptor_for(class_idx)
        dotted = _descriptor_to_dotted(descriptor)
        superclass = (_descriptor_to_dotted(descriptor_for(super_idx))
                      if super_idx != _NO_INDEX else None) or None
        methods: tuple[str, ...] = ()
        fields: tuple[str, ...] = ()
        static_idxs: list[int] = []
        if class_data_off:
            methods, fields, static_idxs = _read_class_data(
                f, class_data_off, file_size, dotted,
                field_names, method_names, en, code_spans,
            )
        classes.append(DexClass(descriptor=descriptor, name=dotted,
                                superclass=superclass,
                                method_names=methods, field_names=fields))
        if static_values_off and static_idxs:
            classes_static.append((static_idxs, static_values_off))
    return classes, code_spans, classes_static


def _read_class_data(f: BinaryIO, off: int, file_size: int, class_name: str,
                     field_names: list[str], method_names: list[str], en: str,
                     code_spans: list[tuple[int, int, str, str]],
                     ) -> tuple[tuple[str, ...], tuple[str, ...], list[int]]:
    """Parse one class_data_item: collect member names, append method code-spans, and return
    the ordered static field indices (so a `static_values` array can be aligned to them).

    Read a bounded window (class_data_items are small uleb streams); a class too large to
    fit the window degrades to the names that did fit rather than raising.
    """
    window = min(_MAX_CLASS_DATA, max(file_size - off, 0))
    if window <= 0:
        return (), (), []
    f.seek(off)
    buf = f.read(window)

    pos = 0
    static_n, pos = _uleb128(buf, pos)
    instance_n, pos = _uleb128(buf, pos)
    direct_n, pos = _uleb128(buf, pos)
    virtual_n, pos = _uleb128(buf, pos)

    fields: list[str] = []
    methods: list[str] = []
    static_idxs: list[int] = []
    try:
        pos = _read_encoded_fields(buf, pos, static_n, field_names, fields, static_idxs)
        pos = _read_encoded_fields(buf, pos, instance_n, field_names, fields)
        pos = _read_encoded_methods(f, buf, pos, direct_n, file_size, class_name,
                                    method_names, en, code_spans, methods)
        _read_encoded_methods(f, buf, pos, virtual_n, file_size, class_name,
                              method_names, en, code_spans, methods)
    except DexError:
        pass    # truncated window for an oversized class: keep what parsed
    return tuple(methods), tuple(fields), static_idxs


def _read_encoded_fields(buf: bytes, pos: int, count: int,
                         field_names: list[str], out: list[str],
                         idx_out: list[int] | None = None) -> int:
    idx = 0
    for n in range(count):
        diff, pos = _uleb128(buf, pos)
        _access, pos = _uleb128(buf, pos)
        idx = diff if n == 0 else idx + diff
        if idx_out is not None:
            idx_out.append(idx)         # every static field, in order, for static_values
        if 0 <= idx < len(field_names):
            out.append(field_names[idx])
    return pos


def _read_encoded_methods(f: BinaryIO, buf: bytes, pos: int, count: int, file_size: int,
                          class_name: str, method_names: list[str], en: str,
                          code_spans: list[tuple[int, int, str, str]],
                          out: list[str]) -> int:
    idx = 0
    for n in range(count):
        diff, pos = _uleb128(buf, pos)
        _access, pos = _uleb128(buf, pos)
        code_off, pos = _uleb128(buf, pos)
        idx = diff if n == 0 else idx + diff
        name = method_names[idx] if 0 <= idx < len(method_names) else ""
        out.append(name)
        if code_off and len(code_spans) < _MAX_METHODS:
            span = _code_span(f, code_off, file_size, en)
            if span is not None:
                code_spans.append((span[0], span[1], class_name, name))
    return pos


def _code_span(f: BinaryIO, code_off: int, file_size: int, en: str) -> tuple[int, int] | None:
    """[code_off, code_off + header + insns_bytes) from the code_item header only."""
    if code_off + _CODE_ITEM_HEADER > file_size:
        return None
    f.seek(code_off)
    hdr = f.read(_CODE_ITEM_HEADER)
    if len(hdr) < _CODE_ITEM_HEADER:
        return None
    (insns_size,) = struct.unpack_from(en + "I", hdr, 12)
    if insns_size > _MAX_INSNS_UNITS:
        return None
    end = code_off + _CODE_ITEM_HEADER + insns_size * 2
    return (code_off, min(end, file_size))
