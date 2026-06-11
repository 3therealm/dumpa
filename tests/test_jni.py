"""decode_jni: JNI short symbol names -> (dotted class, method)."""

from __future__ import annotations

import pytest

from dumpa.core.jni import decode_jni


@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("Java_com_foo_Bar_method", ("com.foo.Bar", "method")),
        ("Java_Bar_method", ("Bar", "method")),
        # _1 -> underscore inside an identifier
        ("Java_com_foo_Bar_native_1m", ("com.foo.Bar", "native_m")),
        # overload signature after "__" is stripped
        ("Java_com_foo_Bar_m__II", ("com.foo.Bar", "m")),
        ("Java_com_foo_Bar_m__Ljava_lang_String_2", ("com.foo.Bar", "m")),
        # _0XXXX unicode escape (U+00e9 = é)
        ("Java_com_foo_Bar_caf_000e9", ("com.foo.Bar", "café")),
    ],
)
def test_decode(symbol: str, expected: tuple[str, str]) -> None:
    assert decode_jni(symbol) == expected


@pytest.mark.parametrize(
    "symbol",
    [
        "",
        "abc",
        "JavaCritical_com_foo_Bar_m",   # not the plain Java_ prefix
        "Java_",                        # nothing after the prefix
        "Java_OnlyClass",               # no method segment
        "Java_com_foo_Bar_caf_00zz",    # malformed unicode escape
    ],
)
def test_rejects(symbol: str) -> None:
    assert decode_jni(symbol) is None
