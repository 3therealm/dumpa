"""core.unrealcrypto: optional AES-ECB + LZ4 codecs (dumpa[unreal] extra)."""

from __future__ import annotations

import pytest

from dumpa.core import unrealcrypto


def test_aes_ecb_roundtrip() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = bytes(range(32))                       # AES-256
    plaintext = b"UnrealPakSecret!" * 2          # 32 bytes, block-aligned
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ciphertext = enc.update(plaintext) + enc.finalize()

    assert unrealcrypto.decrypt_aes_ecb(ciphertext, key) == plaintext


def test_aes_wrong_key_does_not_recover_plaintext() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    plaintext = b"A" * 16
    enc = Cipher(algorithms.AES(bytes(range(32))), modes.ECB()).encryptor()
    ciphertext = enc.update(plaintext) + enc.finalize()

    assert unrealcrypto.decrypt_aes_ecb(ciphertext, b"\x00" * 32) != plaintext


def test_aes_rejects_misaligned_data() -> None:
    assert unrealcrypto.decrypt_aes_ecb(b"not-a-block", b"\x01" * 32) is None


def test_aes_rejects_bad_key_length() -> None:
    assert unrealcrypto.decrypt_aes_ecb(b"\x00" * 16, b"short-key") is None


def test_aes_rejects_empty() -> None:
    assert unrealcrypto.decrypt_aes_ecb(b"", b"\x01" * 32) is None


def test_lz4_block_roundtrip() -> None:
    pytest.importorskip("lz4")
    import lz4.block

    plaintext = b"the quick brown fox " * 64
    compressed = lz4.block.compress(plaintext, store_size=False)
    assert unrealcrypto.decompress_lz4_block(compressed, len(plaintext)) == plaintext


def test_lz4_wrong_size_returns_none() -> None:
    pytest.importorskip("lz4")
    import lz4.block

    plaintext = b"data" * 32
    compressed = lz4.block.compress(plaintext, store_size=False)
    assert unrealcrypto.decompress_lz4_block(compressed, len(plaintext) + 1) is None


def test_availability_flags_are_bool() -> None:
    assert isinstance(unrealcrypto.aes_available(), bool)
    assert isinstance(unrealcrypto.lz4_available(), bool)
