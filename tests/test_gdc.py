"""Tests for the zero-dep Godot GDScript token-buffer parser (core.gdc)."""

from __future__ import annotations

import struct

from _gdc_build import build_gdc_v3, build_gdc_v4
from _gdc_build import int_variant as _int_variant
from _gdc_build import str_variant as _str_variant

from dumpa.core import gdc

_MAGIC = b"GDSC"


def test_not_a_gdc_returns_none() -> None:
    assert gdc.parse(b"not a gdc buffer at all") is None


def test_godot3_identifiers_and_string_constants() -> None:
    data = build_gdc_v3(["player_speed", "url"],
                        [_int_variant(42), _str_variant("https://api.example/cfg")])
    info = gdc.parse(data)
    assert info is not None
    assert not info.godot4
    assert not info.compressed
    assert "player_speed" in info.strings
    assert "url" in info.strings
    # the INT constant is skipped, the STRING after it is still reached
    assert "https://api.example/cfg" in info.strings


def test_godot4_identifiers_and_string_constants() -> None:
    data = build_gdc_v4(["NetworkManager", "endpoint"],
                        [_str_variant("https://prod.example/v2")])
    info = gdc.parse(data)
    assert info is not None
    assert info.godot4
    assert "NetworkManager" in info.strings
    assert "endpoint" in info.strings
    assert "https://prod.example/v2" in info.strings


def test_godot3_identifier_padding_handled() -> None:
    # "ab" stores as ab\x00 padded to a 4-byte boundary; the parser must strip XORed padding.
    data = build_gdc_v3(["ab"], [_str_variant("https://pad.example/x")])
    info = gdc.parse(data)
    assert info is not None
    assert "ab" in info.strings
    assert "https://pad.example/x" in info.strings


def test_unsupported_version_decodes_nothing() -> None:
    # version 99 is shaped like a Godot 3 buffer but Godot rejects it (>13, !=101).
    data = build_gdc_v3(["not_real_but_parsed"],
                        [_str_variant("https://fake.example")], version=99)
    info = gdc.parse(data)
    assert info is not None
    assert info.version == 99
    assert info.strings == []           # surfaced header, decoded nothing


def test_godot4_v100_20byte_header() -> None:
    # Godot 4.3/4.4 write tokenizer version 100 with a 20-byte body header.
    data = build_gdc_v4(["NetworkManager"], [_str_variant("https://v100.example/cfg")],
                        version=100)
    info = gdc.parse(data)
    assert info is not None
    assert info.godot4
    assert info.version == 100
    assert "NetworkManager" in info.strings
    assert "https://v100.example/cfg" in info.strings


def test_godot4_compressed_body_deferred() -> None:
    # decompressed_size != 0 marks a Zstd body we cannot decode without the dep.
    data = _MAGIC + struct.pack("<II", 101, 1024) + b"\x28\xb5\x2f\xfd payload"
    info = gdc.parse(data)
    assert info is not None
    assert info.compressed
    assert info.strings == []


def test_excessive_identifier_count_rejected() -> None:
    # id_count beyond the anti-DoS cap is rejected before any large list is built.
    data = _MAGIC + struct.pack("<IIIII", 13, 2_000_000, 0, 0, 0)
    info = gdc.parse(data)
    assert info is not None
    assert info.strings == []


def test_truncated_buffer_is_fail_soft() -> None:
    full = build_gdc_v3(["abc"], [_str_variant("https://x.example/y")])
    info = gdc.parse(full[:18])      # chop mid-table
    assert info is not None          # partial/empty, never raises
