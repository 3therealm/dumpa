"""Decode JNI short symbol names back to their Java class + method.

A native method exported for JNI is named ``Java_<mangled-class>_<method>`` where the
class FQN's ``/`` separators become ``_`` and special characters are escaped (``_1`` -> ``_``,
``_2`` -> ``;``, ``_3`` -> ``[``, ``_0XXXX`` -> the U+XXXX code point). Overloaded methods
append ``__<mangled-arg-signature>``. Decoding these lets the cross-reference index join a
native symbol to the dex/manifest/dump.cs class it bridges.

This recovers the **class** reliably (the join key the xref needs); the method is
best-effort, since the short form is genuinely ambiguous when an identifier's own leading
underscore abuts a separator. C++ Itanium ``_Z`` demangling lives in
:mod:`dumpa.core.cppname`.
"""

from __future__ import annotations

_PREFIX = "Java_"
_HEX = "0123456789abcdefABCDEF"


def decode_jni(symbol: str) -> tuple[str, str] | None:
    """``Java_com_foo_Bar_native_1m`` -> ``("com.foo.Bar", "native_m")``; else ``None``.

    Returns None for non-JNI names (no ``Java_`` prefix), malformed escapes, or names that
    do not split into at least a class and a method.
    """
    if not symbol.startswith(_PREFIX):
        return None
    body = symbol[len(_PREFIX):]
    # Strip an overload's mangled argument signature (name and signature joined by "__").
    sep = body.find("__")
    if sep != -1:
        body = body[:sep]
    if not body:
        return None

    segments: list[str] = []
    cur: list[str] = []
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch != "_":
            cur.append(ch)
            i += 1
            continue
        nxt = body[i + 1] if i + 1 < n else ""
        if nxt == "1":
            cur.append("_")
            i += 2
        elif nxt == "2":
            cur.append(";")
            i += 2
        elif nxt == "3":
            cur.append("[")
            i += 2
        elif nxt == "0":
            hexs = body[i + 2:i + 6]
            if len(hexs) != 4 or any(c not in _HEX for c in hexs):
                return None
            cur.append(chr(int(hexs, 16)))
            i += 6
        else:
            # A structural separator: ends the current package/class/method segment.
            segments.append("".join(cur))
            cur = []
            i += 1
    segments.append("".join(cur))

    if len(segments) < 2:
        return None
    method = segments[-1]
    cls = ".".join(segments[:-1])
    if not cls or not method:
        return None
    return (cls, method)
