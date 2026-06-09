"""Xref JSON round-trip + renderers."""

from __future__ import annotations

from pathlib import Path

from dumpa.core.report import Location
from dumpa.core.xref import (
    Appearance,
    EntityType,
    Layer,
    Xref,
    XrefEntity,
    XrefProvenance,
    read_xref,
    render_xref_entity,
    render_xref_list,
    write_xref,
)


def _sample() -> Xref:
    ent = XrefEntity(
        type=EntityType.CLASS, key="com.foo.Bar", display="com.foo.Bar",
        appearances=(
            Appearance(Layer.NATIVE, Location(file_path="lib/arm64-v8a/libfoo.so", rva=4096)),
            Appearance(Layer.SMALI, Location(file_path="classes.dex", dex_class="com.foo.Bar")),
        ),
        aliases=("com.foo.Bar",),
    )
    prov = XrefProvenance(input_sha256="abc", built="t",
                          layers_present=(Layer.NATIVE, Layer.SMALI))
    return Xref(provenance=prov, entities=(ent,))


def test_round_trip(tmp_path: Path) -> None:
    xref = _sample()
    path = tmp_path / "xref.json"
    write_xref(xref, path)
    loaded = read_xref(path)
    assert loaded == xref


def test_read_missing_returns_none(tmp_path: Path) -> None:
    assert read_xref(tmp_path / "nope.json") is None


def test_render_list_threshold() -> None:
    out = render_xref_list(_sample(), min_layers=2)
    assert "com.foo.Bar" in out
    assert "native,smali" in out
    # raising the bar drops the 2-layer entity
    assert "com.foo.Bar" not in render_xref_list(_sample(), min_layers=3)


def test_render_entity_groups_by_layer() -> None:
    out = render_xref_entity(_sample().entities[0])
    assert "[class] com.foo.Bar" in out
    assert "native:" in out
    assert "smali:" in out
    assert "aliases:" in out
