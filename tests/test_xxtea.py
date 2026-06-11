"""Tests for the zero-dep XXTEA decrypt primitive (core.xxtea)."""

from __future__ import annotations

import pytest
from _xxtea_build import encrypt, make_signed

from dumpa.core.xxtea import const_default_sign, decrypt, decrypt_signed


@pytest.mark.parametrize("plaintext", [
    b"a",
    b"hello world",
    b"x" * 64,
    b'{"k":1,"name":"cocos"}',
    bytes(range(200)),
])
def test_round_trip(plaintext: bytes) -> None:
    key = b"my-secret-key-16"
    assert decrypt(encrypt(plaintext, key), key) == plaintext


def test_short_key_padded() -> None:
    # A key shorter than 16 bytes is zero-padded by both sides identically.
    plaintext = b"padded-key path"
    key = b"short"
    assert decrypt(encrypt(plaintext, key), key) == plaintext


def test_wrong_key_does_not_recover() -> None:
    blob = encrypt(b"sensitive script body", b"correct-key-0001")
    assert decrypt(blob, b"wrong-key-000002") != b"sensitive script body"


def test_empty_input() -> None:
    assert decrypt(b"", b"any") == b""


def test_decrypt_signed_strips_sign() -> None:
    key, sign = b"k", b"XXTEA"
    blob = make_signed(b"local script", key, sign)
    assert decrypt_signed(blob, key, sign) == b"local script"


def test_decrypt_signed_custom_sign() -> None:
    key, sign = b"k", b"MYGAME"
    blob = make_signed(b"body", key, sign)
    assert decrypt_signed(blob, key, sign) == b"body"


def test_decrypt_signed_mismatch_returns_none() -> None:
    blob = make_signed(b"body", b"k", b"XXTEA")
    assert decrypt_signed(blob, b"k", b"NOPE") is None


def test_default_sign_constant() -> None:
    assert const_default_sign == b"XXTEA"
