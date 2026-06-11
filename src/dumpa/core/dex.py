"""Zero-dependency structural DEX parser for `classesN.dex`.

Reads the DEX header and the string / type / field / method / class_def pools straight
from the binary with the stdlib alone (`struct`) — same no-extra-deps ethos as `core.elf`
and `core.axml`. It is *almost* structural-only: it reads `code_item` headers to size each
method's byte span, and decodes exactly two Dalvik instructions — `const-string` (0x1a)
and `const-string/jumbo` (0x1b) — to build a string-constant cross-reference. Every other
opcode is advanced past by width alone; their operands are never interpreted.

It powers three things: a per-file class/method/field inventory (the `dex` scanner); a
file-offset -> (class, method) map (`DexFile.locate`), so a finding located by byte offset
inside a `.dex` — e.g. a tracker class-path string a content scanner matched — can report
the owning class (and method, when the offset lands in bytecode); and a string-constant
xref (`DexFile.locate_string_xref`), so an offset inside an *arbitrary* string constant —
a hardcoded secret, endpoint URL, or tracker domain — resolves to the method(s) whose
`const-string` loads it.

What `locate` resolves:
  * offset inside a `code_item`     -> (owning class, method)        — exact
  * offset inside a class descriptor string -> (the class it names, None)

What `locate_string_xref` adds:
  * offset inside any string_data range -> the methods that `const-string`-load it

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
class DexFile:
    """Parsed structural metadata for one .dex."""
    version: int                     # 35..41 from "dex\n0NN\0"
    classes: tuple[DexClass, ...]
    # Sorted, non-overlapping spans for offset -> owner resolution.
    code_spans: tuple[tuple[int, int, str, str], ...]   # (start, end, class, method)
    desc_spans: tuple[tuple[int, int, str], ...]        # (start, end, dotted class)
    # Sorted spans over string_data of const-string-referenced strings.
    xref_spans: tuple[tuple[int, int, tuple[tuple[str, str], ...]], ...] = ()

    def locate(self, offset: int) -> tuple[str, str | None] | None:
        """Map a file byte offset to (dotted_class, method_name|None), or None.

        A code-item hit yields class + method; a class-descriptor-string hit yields the
        class the string names (method None). Anything else is None.
        """
        starts = [s[0] for s in self.code_spans]
        i = bisect.bisect_right(starts, offset) - 1
        if 0 <= i < len(self.code_spans):
            start, end, cls, meth = self.code_spans[i]
            if start <= offset < end:
                return (cls, meth)
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
    method_names = _read_member_names(f, en, method_ids_off, method_ids_size, strings)

    classes, code_spans = _read_classes(
        f, en, class_defs_off, class_defs_size, file_size,
        strings, type_desc, field_names, method_names,
    )
    desc_spans = _build_desc_spans(type_desc, strings, str_content)
    code_spans.sort(key=lambda s: s[0])
    # const-string operands are little-endian code units; skip the xref on the (essentially
    # theoretical) reverse-endian dex rather than misread them into bogus attributions.
    xref_spans = (_build_xref_spans(f, code_spans, str_content, len(strings))
                  if en == "<" else ())
    return DexFile(version=version, classes=tuple(classes),
                   code_spans=tuple(code_spans), desc_spans=tuple(desc_spans),
                   xref_spans=xref_spans)


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
                  ) -> tuple[list[DexClass], list[tuple[int, int, str, str]]]:
    if size == 0:
        return [], []
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
    for i in range(size):
        (class_idx, _access, super_idx, _ifaces, _src, _ann,
         class_data_off, _statics) = struct.unpack_from(en + "IIIIIIII", table, i * 32)
        descriptor = descriptor_for(class_idx)
        dotted = _descriptor_to_dotted(descriptor)
        superclass = (_descriptor_to_dotted(descriptor_for(super_idx))
                      if super_idx != _NO_INDEX else None) or None
        methods: tuple[str, ...] = ()
        fields: tuple[str, ...] = ()
        if class_data_off:
            methods, fields = _read_class_data(
                f, class_data_off, file_size, dotted,
                field_names, method_names, en, code_spans,
            )
        classes.append(DexClass(descriptor=descriptor, name=dotted,
                                superclass=superclass,
                                method_names=methods, field_names=fields))
    return classes, code_spans


def _read_class_data(f: BinaryIO, off: int, file_size: int, class_name: str,
                     field_names: list[str], method_names: list[str], en: str,
                     code_spans: list[tuple[int, int, str, str]],
                     ) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Parse one class_data_item: collect member names and append method code-spans.

    Read a bounded window (class_data_items are small uleb streams); a class too large to
    fit the window degrades to the names that did fit rather than raising.
    """
    window = min(_MAX_CLASS_DATA, max(file_size - off, 0))
    if window <= 0:
        return (), ()
    f.seek(off)
    buf = f.read(window)

    pos = 0
    static_n, pos = _uleb128(buf, pos)
    instance_n, pos = _uleb128(buf, pos)
    direct_n, pos = _uleb128(buf, pos)
    virtual_n, pos = _uleb128(buf, pos)

    fields: list[str] = []
    methods: list[str] = []
    try:
        pos = _read_encoded_fields(buf, pos, static_n, field_names, fields)
        pos = _read_encoded_fields(buf, pos, instance_n, field_names, fields)
        pos = _read_encoded_methods(f, buf, pos, direct_n, file_size, class_name,
                                    method_names, en, code_spans, methods)
        _read_encoded_methods(f, buf, pos, virtual_n, file_size, class_name,
                              method_names, en, code_spans, methods)
    except DexError:
        pass    # truncated window for an oversized class: keep what parsed
    return tuple(methods), tuple(fields)


def _read_encoded_fields(buf: bytes, pos: int, count: int,
                         field_names: list[str], out: list[str]) -> int:
    idx = 0
    for n in range(count):
        diff, pos = _uleb128(buf, pos)
        _access, pos = _uleb128(buf, pos)
        idx = diff if n == 0 else idx + diff
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
