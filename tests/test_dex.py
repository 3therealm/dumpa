"""Tests for the zero-dep structural DEX parser (core.dex)."""

from __future__ import annotations

from pathlib import Path

from _dex_build import build_dex

from dumpa.core.dex import DexFile, _descriptor_to_dotted, parse_dex


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "classes.dex"
    p.write_bytes(data)
    return p


def test_parse_inventory(tmp_path: Path) -> None:
    data, _ = build_dex()
    dex = parse_dex(_write(tmp_path, data))
    assert dex is not None
    assert dex.version == 35
    assert len(dex.classes) == 1
    cls = dex.classes[0]
    assert cls.descriptor == "Lcom/x/A;"
    assert cls.name == "com.x.A"
    assert cls.superclass == "java.lang.Object"
    assert cls.method_names == ("foo",)
    assert cls.field_names == ("bar",)


def test_descriptor_to_dotted() -> None:
    assert _descriptor_to_dotted("Lcom/google/firebase/Foo;") == "com.google.firebase.Foo"
    assert _descriptor_to_dotted("I") == "I"          # primitive passes through
    assert _descriptor_to_dotted("[I") == "[I"        # array passes through


def test_locate_code_offset_resolves_method(tmp_path: Path) -> None:
    data, info = build_dex()
    dex = parse_dex(_write(tmp_path, data))
    assert dex is not None
    inside = info["code_off"] + 17                     # within the insns of method foo
    assert inside < info["code_end"]
    assert dex.locate(inside) == ("com.x.A", "foo")


def test_locate_descriptor_string_resolves_class_only(tmp_path: Path) -> None:
    data, info = build_dex()
    dex = parse_dex(_write(tmp_path, data))
    assert dex is not None
    start, end = info["str_content"]["Lcom/x/A;"]
    assert dex.locate(start + 3) == ("com.x.A", None)  # offset inside the descriptor bytes
    assert start < end


def test_locate_plain_string_is_none(tmp_path: Path) -> None:
    data, info = build_dex()
    dex = parse_dex(_write(tmp_path, data))
    assert dex is not None
    start, _ = info["str_content"]["hello"]            # not a class descriptor
    assert dex.locate(start) is None


def test_string_xref_resolves_loading_method(tmp_path: Path) -> None:
    data, info = build_dex()
    dex = parse_dex(_write(tmp_path, data))
    assert dex is not None
    start, end = info["str_content"][info["ref_const"]]
    assert dex.locate_string_xref(start) == (("com.x.A", "foo"),)
    assert dex.locate_string_xref(end - 1) == (("com.x.A", "foo"),)
    # locate() still finds no structural owner for a plain string constant.
    assert dex.locate(start) is None


def test_string_xref_unreferenced_is_empty(tmp_path: Path) -> None:
    data, info = build_dex()
    dex = parse_dex(_write(tmp_path, data))
    assert dex is not None
    start, _ = info["str_content"]["hello"]            # never loaded by code
    assert dex.locate_string_xref(start) == ()


def test_string_xref_skips_payload_bytes(tmp_path: Path) -> None:
    """A fill-array-data-payload whose body contains a const-string-looking byte run must
    be skipped whole — its bytes must not be misread into a bogus xref."""
    import struct
    body = (struct.pack("<HH", 0x001A, 6)                       # const-string v0, string@6
            + struct.pack("<HHI", 0x0300, 1, 4)                 # fill-array-data-payload
            + struct.pack("<HH", 0x001A, 5))                    # payload data: looks like @5
    data, info = build_dex(insns=body)
    dex = parse_dex(_write(tmp_path, data))
    assert dex is not None
    ref_start, _ = info["str_content"][info["ref_const"]]
    hello_start, _ = info["str_content"]["hello"]
    assert dex.locate_string_xref(ref_start) == (("com.x.A", "foo"),)   # the real load
    assert dex.locate_string_xref(hello_start) == ()                    # payload byte ignored


def test_locate_gap_is_none(tmp_path: Path) -> None:
    data, _ = build_dex()
    dex = parse_dex(_write(tmp_path, data))
    assert dex is not None
    assert dex.locate(0) is None                       # the header, owned by nothing
    assert dex.locate(len(data) + 1000) is None


def test_non_dex_returns_none(tmp_path: Path) -> None:
    assert parse_dex(_write(tmp_path, b"not a dex at all, padding padding")) is None


def test_truncated_returns_none(tmp_path: Path) -> None:
    data, _ = build_dex()
    assert parse_dex(_write(tmp_path, data[:60])) is None


def test_bad_version_returns_none(tmp_path: Path) -> None:
    data, _ = build_dex(version=b"zz\x00\x00")
    assert parse_dex(_write(tmp_path, data)) is None


def test_returns_dexfile_type(tmp_path: Path) -> None:
    data, _ = build_dex()
    assert isinstance(parse_dex(_write(tmp_path, data)), DexFile)
