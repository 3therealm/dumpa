"""Unit tests for the Itanium C++ ``_Z`` demangler (core/cppname.py)."""

from __future__ import annotations

import pytest

from dumpa.core.cppname import demangle_cpp


def test_nested_method() -> None:
    got = demangle_cpp("_ZN3Foo3Bar3bazEv")
    assert got is not None
    assert got.qualified == "Foo::Bar::baz"
    assert got.cls == "Foo::Bar"
    assert got.member == "baz"


def test_single_namespace_method() -> None:
    got = demangle_cpp("_ZN7cocos2d6Sprite4initEv")
    assert got is not None
    assert got.qualified == "cocos2d::Sprite::init"
    assert got.cls == "cocos2d::Sprite"
    assert got.member == "init"


def test_constructor() -> None:
    got = demangle_cpp("_ZN3FooC1Ev")
    assert got is not None
    assert got.cls == "Foo"
    assert got.member == "Foo"


def test_nested_constructor() -> None:
    got = demangle_cpp("_ZN3Foo3BarC2Ev")
    assert got is not None
    assert got.qualified == "Foo::Bar::Bar"
    assert got.cls == "Foo::Bar"
    assert got.member == "Bar"


def test_destructor() -> None:
    got = demangle_cpp("_ZN3FooD0Ev")
    assert got is not None
    assert got.cls == "Foo"
    assert got.member == "~Foo"


def test_free_function() -> None:
    got = demangle_cpp("_Z3foov")
    assert got is not None
    assert got.qualified == "foo"
    assert got.cls == ""
    assert got.member == "foo"


def test_free_function_with_args_ignored() -> None:
    got = demangle_cpp("_Z3fooi")          # foo(int) — arg type ignored
    assert got is not None
    assert got.member == "foo"


def test_std_nested() -> None:
    got = demangle_cpp("_ZNSt6vectorEv")
    assert got is not None
    assert got.qualified == "std::vector"
    assert got.cls == "std"
    assert got.member == "vector"


def test_clang_double_underscore_prefix() -> None:
    got = demangle_cpp("__ZN3Foo3barEv")
    assert got is not None
    assert got.qualified == "Foo::bar"


@pytest.mark.parametrize("sym", [
    "Java_com_foo_Bar_init",   # JNI, not C++
    "plain_c_symbol",          # no _Z prefix
    "_Z",                      # truncated
    "_ZN",                     # nested, no body
    "_ZN3Foo",                 # nested, missing E
    "_ZN99FooE",               # length runs past the string
    "_ZN3FooIiEE",             # template-args — out of subset
    "_Z",                      # empty body
])
def test_unsupported_returns_none(sym: str) -> None:
    assert demangle_cpp(sym) is None
