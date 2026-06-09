"""Stream method signatures out of an Il2CppDumper ``dump.cs``.

A ``dump.cs`` is tens to hundreds of MB on a real game, so this reads it line by line
and yields one stable identity per method — never loading the file whole (the
Architecture Foundations streaming rule). Identity is ``Namespace.Type::declaration``
with the address comment dropped: Il2CppDumper prints the RVA/Offset/VA on a *separate*
``// RVA: ...`` comment line above each method, so the declaration line itself is already
free of addresses and compares equal across rebuilds. That is what lets ``dumpa diff``
report which methods a game update added or removed rather than drowning in churn.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

# `// Namespace: Foo.Bar` precedes each type; empty for the global namespace.
_NS_RE = re.compile(r'^\s*//\s*Namespace:\s*(.*)$')
# A type declaration: a class/struct/enum/interface keyword + the type name token.
_TYPE_RE = re.compile(r'\b(?:class|struct|enum|interface)\s+([A-Za-z_][\w`<>.]*)')
# Strip a method body / declaration terminator from the end of a decl line.
_TAIL_RE = re.compile(r'\s*(?:\{\s*\}|;)\s*$')


def _is_method(stripped: str) -> bool:
    """A non-comment declaration line carrying a parameter list and a body/terminator."""
    if not stripped or stripped.startswith('//'):
        return False
    if '(' not in stripped or ')' not in stripped:
        return False
    return stripped.endswith(('}', ';'))


def _method_sig(stripped: str) -> str:
    """Normalize a method decl line to a stable signature (drop body, collapse spaces)."""
    return re.sub(r'\s+', ' ', _TAIL_RE.sub('', stripped))


def iter_method_sigs(dump_cs: Path) -> Iterator[str]:
    """Yield ``Namespace.Type::signature`` identities, streaming the file line by line.

    Fail-soft: malformed/undecodable lines are skipped, not raised on. Methods seen before
    their enclosing type is known are dropped (no spurious ``::`` prefixes).
    """
    namespace = ''
    typename = ''
    with dump_cs.open('r', encoding='utf-8', errors='replace') as handle:
        for line in handle:
            ns = _NS_RE.match(line)
            if ns is not None:
                namespace = ns.group(1).strip()
                continue
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            type_match = _TYPE_RE.search(stripped)
            if type_match is not None and '(' not in stripped:
                typename = type_match.group(1)
                continue
            if typename and _is_method(stripped):
                prefix = f'{namespace}.{typename}' if namespace else typename
                yield f'{prefix}::{_method_sig(stripped)}'


def method_set(dump_cs: Path) -> set[str]:
    """All method-signature identities in a dump.cs as a set (bounded by method count)."""
    return set(iter_method_sigs(dump_cs))
