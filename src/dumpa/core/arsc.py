"""Zero-dependency parser for the Android binary resource table (`resources.arsc`).

`resources.arsc` is the compiled resource table an apk ships instead of plain-text
resources: a global value string pool plus one or more *packages*, each carrying a
type string pool (`string`, `layout`, `drawable`, ...), a key string pool (the resource
entry names), and a stream of typed entry chunks. This module decodes that with the
stdlib alone, reusing the shared `core.respool` string-pool machinery (the same format
`core.axml` reads) — matching the toolkit's no-extra-deps parser ethos (`elf`, `dex`,
`axml`, `pck`).

It is deliberately *value-and-name only*: for each entry it resolves the resource name
and, for string-typed entries, the pooled string value plus that value's absolute byte
span in the file. Those spans power `ArscTable.locate(offset)` — mapping a byte offset a
content scanner matched inside `resources.arsc` (a URL, an API key) back to the resource
that owns it, the same offset->owner trick as `DexFile.locate`.

Parsing is lenient: a malformed individual entry/type/package is skipped rather than
fatal, so a single bad record never loses the rest of a real table; only a table whose
top-level header is not a resource table raises `ArscError`.

References: AOSP `ResourceTypes.h` (ResTable_header, ResTable_package, ResTable_typeSpec,
ResTable_type, ResTable_entry, Res_value).
"""

from __future__ import annotations

import bisect
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from dumpa.core.errors import ArscError, ResChunkError
from dumpa.core.respool import decode_string_pool, decode_string_pool_with_spans, u16, u32

# Chunk types (ResChunk_header.type).
_RES_STRING_POOL = 0x0001
_RES_TABLE = 0x0002
_RES_TABLE_PACKAGE = 0x0200
_RES_TABLE_TYPE = 0x0201

# ResTable_type.flags.
_TYPE_FLAG_SPARSE = 0x01
_TYPE_FLAG_OFFSET16 = 0x02

# ResTable_entry.flags.
_ENTRY_FLAG_COMPLEX = 0x0001
_ENTRY_FLAG_COMPACT = 0x0008

# Res_value.dataType we resolve (a pooled string value).
_RES_VALUE_STRING = 0x03

_NO_ENTRY = 0xFFFFFFFF

# Defensive caps so pathological input cannot exhaust memory / time.
_MAX_PACKAGES = 256
_MAX_TYPES = 4096
_MAX_ENTRIES_PER_TYPE = 1_000_000


@dataclass(frozen=True)
class ArscEntry:
    """One resolved resource entry: its type, name, and (for strings) value + byte span."""
    type_name: str
    name: str
    value: str | None = None
    value_offset: int | None = None      # absolute offset of the value's bytes in the file


@dataclass(frozen=True)
class ArscPackage:
    """One package in the table (e.g. the app's own `com.example`)."""
    id: int
    name: str
    entries: tuple[ArscEntry, ...]

    def type_counts(self) -> dict[str, int]:
        """Entry count per resource type (`string`, `layout`, `raw`, ...), for a summary."""
        counts: dict[str, int] = {}
        for e in self.entries:
            counts[e.type_name] = counts.get(e.type_name, 0) + 1
        return counts


@dataclass(frozen=True)
class ArscTable:
    """A decoded resource table: its packages plus a value-offset index for `locate`."""
    packages: tuple[ArscPackage, ...]
    # Sorted, non-overlapping (start, end, resource_name, value) spans of string values.
    _spans: tuple[tuple[int, int, str, str], ...] = ()

    def iter_strings(self) -> Iterator[tuple[str, str, str, str, int]]:
        """Yield (package, type_name, name, value, value_offset) for every string entry."""
        for pkg in self.packages:
            for e in pkg.entries:
                if e.value is not None and e.value_offset is not None:
                    yield (pkg.name, e.type_name, e.name, e.value, e.value_offset)

    def locate(self, offset: int) -> tuple[str, str] | None:
        """Map a file byte offset inside a string value to (resource_name, value), else None."""
        starts = [s[0] for s in self._spans]
        i = bisect.bisect_right(starts, offset) - 1
        if 0 <= i < len(self._spans):
            start, end, name, value = self._spans[i]
            if start <= offset < end:
                return (name, value)
        return None


def parse_arsc(data: bytes) -> ArscTable:
    """Decode `resources.arsc` bytes into an `ArscTable`. Raise `ArscError` if not a table."""
    if len(data) < 12:
        raise ArscError("file too small to be a resource table")
    try:
        file_type = u16(data, 0)
        header_size = u16(data, 2)
        table_size = u32(data, 4)
    except ResChunkError as exc:
        raise ArscError(str(exc)) from exc
    if file_type != _RES_TABLE:
        raise ArscError(f"not a resource table (chunk type 0x{file_type:04x})")

    end = min(table_size, len(data)) if table_size else len(data)
    global_strings: list[str] = []
    global_spans: list[tuple[int, int]] = []
    packages: list[ArscPackage] = []
    spans: list[tuple[int, int, str, str]] = []

    off = header_size if header_size >= 12 else 12
    while off + 8 <= end:
        try:
            chunk_type = u16(data, off)
            chunk_size = u32(data, off + 4)
        except ResChunkError:
            break
        if chunk_size < 8 or off + chunk_size > len(data):
            break
        if chunk_type == _RES_STRING_POOL and not global_strings:
            try:
                global_strings, global_spans = decode_string_pool_with_spans(data, off, chunk_size)
            except ResChunkError:
                global_strings, global_spans = [], []
        elif chunk_type == _RES_TABLE_PACKAGE and len(packages) < _MAX_PACKAGES:
            pkg = _parse_package(data, off, chunk_size, global_strings, global_spans, spans)
            if pkg is not None:
                packages.append(pkg)
        off += chunk_size

    spans.sort(key=lambda s: s[0])
    return ArscTable(packages=tuple(packages), _spans=tuple(spans))


def parse_arsc_file(path: Path) -> ArscTable | None:
    """Parse a resources.arsc file; None on any missing/non-table/unreadable input."""
    try:
        return parse_arsc(path.read_bytes())
    except (ArscError, OSError):
        return None


def _read_pool(data: bytes, off: int) -> list[str]:
    """Decode a RES_STRING_POOL chunk located at `off` (size read from its own header)."""
    try:
        return decode_string_pool(data, off, u32(data, off + 4))
    except ResChunkError:
        return []


def _parse_package(data: bytes, off: int, chunk_size: int, global_strings: list[str],
                   global_spans: list[tuple[int, int]],
                   spans: list[tuple[int, int, str, str]]) -> ArscPackage | None:
    """Decode one ResTable_package: its name, type/key pools, and string-resolved entries."""
    try:
        header_size = u16(data, off + 2)
        pkg_id = u32(data, off + 8)
        name = data[off + 12:off + 12 + 256].decode("utf-16-le", "replace").split("\x00", 1)[0]
        type_strings_off = u32(data, off + 268)
        key_strings_off = u32(data, off + 276)
    except ResChunkError:
        return None
    type_strings = _read_pool(data, off + type_strings_off) if type_strings_off else []
    key_strings = _read_pool(data, off + key_strings_off) if key_strings_off else []

    entries: list[ArscEntry] = []
    inner = off + header_size
    table_end = off + chunk_size
    while inner + 8 <= table_end:
        try:
            inner_type = u16(data, inner)
            inner_size = u32(data, inner + 4)
        except ResChunkError:
            break
        if inner_size < 8 or inner + inner_size > len(data):
            break
        if inner_type == _RES_TABLE_TYPE:
            _parse_type(data, inner, type_strings, key_strings,
                        global_strings, global_spans, entries, spans)
        inner += inner_size
    return ArscPackage(id=pkg_id, name=name, entries=tuple(entries))


def _parse_type(data: bytes, off: int, type_strings: list[str], key_strings: list[str],
                global_strings: list[str], global_spans: list[tuple[int, int]],
                entries: list[ArscEntry], spans: list[tuple[int, int, str, str]]) -> None:
    """Decode one ResTable_type chunk, appending resolved entries (names + string values)."""
    try:
        header_size = u16(data, off + 2)
        type_id = data[off + 8]
        flags = data[off + 9]
        entry_count = u32(data, off + 12)
        entries_start = u32(data, off + 16)
    except (ResChunkError, IndexError):
        return
    if entry_count > _MAX_ENTRIES_PER_TYPE:
        return
    # Sparse / 16-bit offset variants are rare in app tables; skip their entries safely.
    if flags & (_TYPE_FLAG_SPARSE | _TYPE_FLAG_OFFSET16):
        return
    type_name = type_strings[type_id - 1] if 1 <= type_id <= len(type_strings) else f"type{type_id}"
    offsets_at = off + header_size
    base = off + entries_start
    for idx in range(entry_count):
        try:
            eo = u32(data, offsets_at + idx * 4)
        except ResChunkError:
            break
        if eo == _NO_ENTRY:
            continue
        resolved = _parse_entry(data, base + eo, type_name, key_strings,
                                global_strings, global_spans)
        if resolved is None:
            continue
        entry, span = resolved
        entries.append(entry)
        if span is not None and entry.value is not None:
            spans.append((span[0], span[1], entry.name, entry.value))


def _parse_entry(data: bytes, entry_off: int, type_name: str, key_strings: list[str],
                 global_strings: list[str], global_spans: list[tuple[int, int]],
                 ) -> tuple[ArscEntry, tuple[int, int] | None] | None:
    """Decode one ResTable_entry (+ trailing Res_value); return (entry, value byte span)."""
    try:
        entry_size = u16(data, entry_off)
        entry_flags = u16(data, entry_off + 2)
        key_idx = u32(data, entry_off + 4)
    except ResChunkError:
        return None
    name = key_strings[key_idx] if 0 <= key_idx < len(key_strings) else ""
    if not name:
        return None
    bare = ArscEntry(type_name=type_name, name=name)
    # Complex (bag/array) and compact entries carry no flat Res_value we resolve here.
    if entry_flags & (_ENTRY_FLAG_COMPLEX | _ENTRY_FLAG_COMPACT):
        return (bare, None)
    value_off = entry_off + entry_size
    try:
        data_type = data[value_off + 3]
        data_val = u32(data, value_off + 4)
    except (ResChunkError, IndexError):
        return (bare, None)
    if data_type != _RES_VALUE_STRING or not (0 <= data_val < len(global_strings)):
        return (bare, None)
    span = global_spans[data_val] if data_val < len(global_spans) else None
    entry = ArscEntry(type_name=type_name, name=name, value=global_strings[data_val],
                      value_offset=span[0] if span is not None else None)
    return (entry, span)
