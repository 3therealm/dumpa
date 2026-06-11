"""xref pure helpers: normalize + layer_of + entity layer set."""

from __future__ import annotations

import pytest

from dumpa.core.report import Location
from dumpa.core.xref import (
    Appearance,
    EntityType,
    Layer,
    XrefEntity,
    layer_of,
    normalize,
)


def test_normalize_domain_folds() -> None:
    assert normalize(EntityType.DOMAIN, "API.Example.COM") == "api.example.com"


def test_normalize_class_descriptor_to_dotted() -> None:
    assert normalize(EntityType.CLASS, "Lcom/foo/Bar;") == "com.foo.Bar"
    assert normalize(EntityType.CLASS, "com/foo/Bar") == "com.foo.Bar"


def test_normalize_class_strips_generic_arity() -> None:
    assert normalize(EntityType.CLASS, "System.Collections.List`1") == "System.Collections.List"


def test_normalize_string_and_symbol_are_exact() -> None:
    assert normalize(EntityType.STRING, "MixedCase") == "MixedCase"
    assert normalize(EntityType.SYMBOL, "Java_com_Foo_x") == "Java_com_Foo_x"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("AndroidManifest.xml", Layer.MANIFEST),
        ("smali/com/foo/Bar.smali", Layer.SMALI),
        ("classes2.dex", Layer.SMALI),
        ("decompiled/com/foo/Bar.java", Layer.JAVA),
        ("lib/arm64-v8a/libfoo.so", Layer.NATIVE),
        ("dump.cs", Layer.DUMPCS),
        ("res/values/strings.xml", Layer.RESOURCE),
        ("resources.arsc", Layer.RESOURCE),
        ("assets/bin/data", Layer.ASSET),
        ("dumps/cocos/decrypted/a.js", Layer.ASSET),
        ("dumps/godot/pck/main.gd", Layer.ASSET),
        ("some/other/file.txt", None),
        (None, None),
    ],
)
def test_layer_of(path: str | None, expected: Layer | None) -> None:
    assert layer_of(path) == expected


def test_entity_layers_dedup() -> None:
    e = XrefEntity(
        type=EntityType.DOMAIN, key="a.com", display="a.com",
        appearances=(
            Appearance(Layer.NATIVE, Location(file_path="lib/x/y.so")),
            Appearance(Layer.NATIVE, Location(file_path="lib/x/z.so")),
            Appearance(Layer.SMALI, Location(file_path="classes.dex")),
        ),
    )
    assert e.layers == frozenset({Layer.NATIVE, Layer.SMALI})
