"""Zero-dependency XXTEA decrypt for cocos2d-x encrypted script bundles.

cocos2d-x ships Ma Bingyao's `xxtea-c` library, not textbook Wheeler/Needham XXTEA.
The differences this implements: words are packed **little-endian**, the original byte
length is carried as a trailing uint32 (appended on encrypt, used to trim padding on
decrypt), and the key is padded/truncated to exactly 16 bytes. An encrypted `.jsc` /
`.luac` is the chosen sign prefix (default `b"XXTEA"`, sometimes app-custom) followed by
this payload.

Decrypt-only by design: the toolkit reads owned/authorized assets, it never re-encrypts.
Same no-extra-deps ethos as `core.elf` / `core.axml` (stdlib `struct` only).
"""

from __future__ import annotations

const_default_sign = b"XXTEA"

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


def _to_bytes(v: list[int]) -> bytes | None:
    """Inverse of `_to_uint_array(..., inc_len=True)`: trim to the trailing length word."""
    length = len(v)
    n = (length << 2) - 4
    m = v[length - 1]
    if m < n - 3 or m > n:
        return None  # length word inconsistent with the data — not a valid payload
    out = bytearray(m)
    for i in range(m):
        out[i] = (v[i >> 2] >> ((i & 3) << 3)) & 0xFF
    return bytes(out)


def _mx(s: int, y: int, z: int, p: int, e: int, k: list[int]) -> int:
    return (((z >> 5 ^ (y << 2) & _MASK) + (y >> 3 ^ (z << 4) & _MASK))
            ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))) & _MASK


def decrypt(data: bytes, key: bytes) -> bytes | None:
    """XXTEA-decrypt a length-prefixed payload. None if the trailing length is invalid.

    A None return is the primary signal that `key` is wrong: the recovered length word
    fails its bounds check. (A wrong key can still yield a passing length by chance and
    return garbage bytes — callers confirm a real key by sniffing the decoded content.)
    """
    if not data:
        return b""
    if len(data) % 4 != 0 or len(data) < 8:
        return None  # a valid payload is whole 32-bit words and holds at least 2 (data+len)
    k = _to_uint_array(_fix_key(key), False)
    v = _to_uint_array(data, False)
    n = len(v) - 1
    y, z = v[0], v[n]
    q = 6 + 52 // (n + 1)
    s = (q * _DELTA) & _MASK
    while s != 0:
        e = (s >> 2) & 3
        for p in range(n, 0, -1):
            z = v[p - 1]
            y = v[p] = (v[p] - _mx(s, y, z, p, e, k)) & _MASK
        z = v[n]
        y = v[0] = (v[0] - _mx(s, y, z, 0, e, k)) & _MASK
        s = (s - _DELTA) & _MASK
    return _to_bytes(v)


def decrypt_signed(blob: bytes, key: bytes, sign: bytes = const_default_sign) -> bytes | None:
    """Verify the `sign` prefix, then XXTEA-decrypt the remainder. None on sign mismatch."""
    if not blob.startswith(sign):
        return None
    return decrypt(blob[len(sign):], key)
