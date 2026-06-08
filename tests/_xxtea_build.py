"""Reference XXTEA codec for tests (Ma Bingyao variant, as bundled by cocos2d-x).

Independent of the product `core.xxtea` (which is decrypt-only) so a shared bug can't
hide: the tests encrypt here and assert `core.xxtea.decrypt` recovers the plaintext.

This is the length-prefixed, little-endian variant (the `xxtea-c` library by Ma Bingyao
that cocos2d-x ships), NOT textbook Wheeler/Needham XXTEA: the original byte length is
appended as a trailing uint32 on encrypt and used to trim padding on decrypt, words are
packed little-endian, and the key is padded/truncated to 16 bytes.
"""

from __future__ import annotations

import struct

_DELTA = 0x9E3779B9
_MASK = 0xFFFFFFFF


def _fix_key(key: bytes) -> bytes:
    return key[:16] if len(key) >= 16 else key + b"\x00" * (16 - len(key))


def _to_uint_array(data: bytes, inc_len: bool) -> list[int]:
    n = (len(data) + 3) // 4
    v = [0] * (n + 1 if inc_len else n)
    for i, b in enumerate(data):
        v[i >> 2] |= b << ((i & 3) << 3)
    if inc_len:
        v[n] = len(data)
    return v


def _to_bytes(v: list[int]) -> bytes:
    return b"".join(struct.pack("<I", w & _MASK) for w in v)


def _mx(s: int, y: int, z: int, p: int, e: int, k: list[int]) -> int:
    return (((z >> 5 ^ (y << 2) & _MASK) + (y >> 3 ^ (z << 4) & _MASK))
            ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))) & _MASK


def encrypt(data: bytes, key: bytes) -> bytes:
    """Length-prefixed XXTEA encrypt; output length is a multiple of 4."""
    if not data:
        return b""
    k = _to_uint_array(_fix_key(key), False)
    v = _to_uint_array(data, True)
    n = len(v) - 1
    y, z = v[0], v[n]
    q = 6 + 52 // (n + 1)
    s = 0
    while q > 0:
        q -= 1
        s = (s + _DELTA) & _MASK
        e = (s >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            z = v[p] = (v[p] + _mx(s, y, z, p, e, k)) & _MASK
        y = v[0]
        z = v[n] = (v[n] + _mx(s, y, z, n, e, k)) & _MASK
    return _to_bytes(v)


def make_signed(data: bytes, key: bytes, sign: bytes) -> bytes:
    """A cocos encrypted script bundle: the sign prefix followed by the XXTEA payload."""
    return sign + encrypt(data, key)
