"""Demangle Itanium C++ ``_Z`` symbol names back to a readable qualified name.

Android native code (NDK / clang) mangles C++ symbols with the Itanium ABI scheme:
``_Z`` followed by an encoding of the (possibly nested) name and then the argument types.
This module recovers just the **name** part — namespaces, class, and member — which is what
the cross-reference index needs to join a native symbol to the class it belongs to, and to
render the symbol legibly. It deliberately does NOT print argument types or full prototypes.

Like :mod:`dumpa.core.jni`, it recovers the class reliably and the member best-effort.
Anything outside the supported subset (templates, operator names, substitutions other than
``St``=``std``, vendor extensions) returns ``None``: a missed demangle leaves the raw symbol
untouched, which is safe; a *wrong* demangle is not, so we never guess.
"""

from __future__ import annotations

from dataclasses import dataclass

_PREFIX = "_Z"


@dataclass(frozen=True)
class CppName:
    """A demangled C++ name: the full ``A::B::member`` plus its class and member parts."""
    qualified: str
    cls: str       # everything before the last "::" ("" for a free function)
    member: str    # the last component


def demangle_cpp(symbol: str) -> CppName | None:
    """``_ZN3Foo3Bar3bazEv`` -> ``CppName("Foo::Bar::baz", "Foo::Bar", "baz")``; else ``None``.

    Returns None for non-``_Z`` names and for any construct outside the supported subset.
    """
    s = symbol
    if s.startswith("__Z"):       # clang/Apple variant: one extra leading underscore
        s = s[1:]
    if not s.startswith(_PREFIX):
        return None
    try:
        components = _Parser(s[len(_PREFIX):]).parse_name()
    except _Bail:
        return None
    member = components[-1]
    return CppName(qualified="::".join(components),
                   cls="::".join(components[:-1]), member=member)


class _Bail(Exception):
    """Internal: an unsupported construct — abandon demangling, demangle_cpp returns None."""


class _Parser:
    """Consumes the ``<name>`` portion of an Itanium encoding; ignores the argument types."""

    def __init__(self, body: str) -> None:
        self.s = body
        self.i = 0

    def _peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def parse_name(self) -> list[str]:
        """Return the name components (e.g. ``["Foo", "Bar", "baz"]``); raise _Bail otherwise."""
        c = self._peek()
        if c == "N":
            return self._nested()
        if c == "S":                     # top-level ``St<name>`` -> ::std::<name>
            self.i += 1
            if self._peek() != "t":
                raise _Bail
            self.i += 1
            comps = ["std"]
            name = self._maybe_source_name()
            if name is not None:
                comps.append(name)
            return comps
        name = self._maybe_source_name()  # unscoped free function / data (args ignored)
        if name is None:
            raise _Bail
        return [name]

    def _nested(self) -> list[str]:
        self.i += 1                       # consume 'N'
        while self._peek() in ("r", "V", "K", "R", "O"):   # CV-/ref-qualifiers
            self.i += 1
        components: list[str] = []
        while True:
            c = self._peek()
            if c == "":
                raise _Bail               # ran off the end without the closing 'E'
            if c == "E":
                self.i += 1
                break
            if c == "I":
                raise _Bail               # template-args — out of subset
            if c in ("C", "D"):
                components.append(self._ctor_dtor(components))
                continue
            if c == "S":                  # only ``St`` (=std) is supported
                self.i += 1
                if self._peek() != "t":
                    raise _Bail
                self.i += 1
                components.append("std")
                continue
            if c.isdigit():
                components.append(self._source_name())
                continue
            raise _Bail                   # operator-name, etc. — out of subset
        if not components:
            raise _Bail
        return components

    def _ctor_dtor(self, components: list[str]) -> str:
        """``C1/C2/C3`` -> the enclosing class name; ``D0/D1/D2`` -> ``~Class``."""
        c = self._peek()
        nxt = self.s[self.i + 1] if self.i + 1 < len(self.s) else ""
        cls_name = components[-1] if components else ""
        if not cls_name:
            raise _Bail
        if c == "C" and nxt in ("1", "2", "3"):
            self.i += 2
            return cls_name
        if c == "D" and nxt in ("0", "1", "2"):
            self.i += 2
            return "~" + cls_name
        raise _Bail

    def _maybe_source_name(self) -> str | None:
        return self._source_name() if self._peek().isdigit() else None

    def _source_name(self) -> str:
        """``<len><identifier>`` — a length-prefixed identifier."""
        j = self.i
        while j < len(self.s) and self.s[j].isdigit():
            j += 1
        length = int(self.s[self.i:j])
        start, end = j, j + length
        if length == 0 or end > len(self.s):
            raise _Bail
        self.i = end
        return self.s[start:end]
