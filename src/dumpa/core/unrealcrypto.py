"""Optional AES + LZ4 codecs for Unreal pak/IoStore decryption (the `dumpa[unreal]` extra).

The zero-dep core (`core.unrealpak` / `core.iostore`) detects encrypted entries/indexes and
non-stdlib compression, then defers. This module supplies the actual codecs when the optional
`dumpa[unreal]` extra is installed — `cryptography` for AES-256 (Unreal encrypts paks with
AES-ECB), `lz4` for LZ4 blocks. Absent → `*_available()` is False and callers fall back to
detect-and-defer, mirroring the UnityPy-backed `unity` extra. Oodle has no open decompressor
and stays deferred regardless.

Every function is fail-soft: bad input or a missing backend returns None, never raises, so a
hostile or unexpected blob degrades to "deferred", not a crash.
"""

from __future__ import annotations

import importlib.util

_AES_KEY_LENS = frozenset({16, 24, 32})
_AES_BLOCK = 16


def aes_available() -> bool:
    """True when `cryptography` is importable (AES decryption is possible)."""
    return importlib.util.find_spec("cryptography") is not None


def lz4_available() -> bool:
    """True when `lz4` is importable (LZ4 block decompression is possible)."""
    return importlib.util.find_spec("lz4") is not None


def decrypt_aes_ecb(data: bytes, key: bytes) -> bytes | None:
    """AES-ECB-decrypt 16-byte-aligned `data` with a 16/24/32-byte `key`.

    Unreal encrypts pak entries and (optionally) the index with AES-256 in ECB mode, padded
    up to the 16-byte block boundary; the caller trims back to the real size afterwards.
    Returns None on misaligned data, a bad key length, or any backend error.
    """
    if not data or len(data) % _AES_BLOCK != 0 or len(key) not in _AES_KEY_LENS:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        return decryptor.update(data) + decryptor.finalize()
    except (ImportError, ValueError, TypeError):
        return None


def decrypt_aes_cfb(data: bytes, key: bytes, iv: bytes) -> bytes | None:
    """AES-CFB-decrypt `data` with a 16/24/32-byte `key` and a 16-byte `iv`.

    Godot's `FileAccessEncrypted` encrypts with AES in full-block CFB (CFB128) mode, not the
    ECB Unreal uses, so this is a distinct primitive sharing the same optional-`cryptography`
    boundary. CFB is a stream mode (no block alignment required); the caller trims the result
    to the stored plaintext length. Empty `data` is allowed — Godot's FileAccessEncrypted wraps
    zero-length files, which decrypt to b"". Returns None on a bad key/iv length or backend error.
    """
    if len(key) not in _AES_KEY_LENS or len(iv) != _AES_BLOCK:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        try:    # CFB moved to `decrepit` in cryptography 49; fall back for older versions.
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.modes import CFB
        decryptor = Cipher(algorithms.AES(key), CFB(iv)).decryptor()
        return decryptor.update(data) + decryptor.finalize()
    except (ImportError, ValueError, TypeError):
        return None


def decompress_lz4_block(data: bytes, uncompressed_size: int) -> bytes | None:
    """LZ4 *block*-format decompress `data` to a known `uncompressed_size`.

    Unreal stores LZ4-compressed blocks in the raw block format (not the frame format) with the
    uncompressed size recorded in the entry, so it is supplied here. Returns None on a size
    mismatch or any backend error.
    """
    if uncompressed_size < 0:
        return None
    try:
        import lz4.block  # type: ignore[import-untyped]
    except ImportError:
        return None
    try:
        out = lz4.block.decompress(data, uncompressed_size=uncompressed_size)
    except lz4.block.LZ4BlockError:
        # Corrupt/short/over-padded input is expected while trimming the AES pad window.
        return None
    return out if len(out) == uncompressed_size else None
