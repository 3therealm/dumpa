"""sha256_file: correct digest, computed via streaming."""

from __future__ import annotations

import hashlib
from pathlib import Path

from dumpa.core.hashing import sha256_file


def test_sha256_matches_hashlib(tmp_path: Path) -> None:
    payload = b"dumpa" * 100_000
    f = tmp_path / "blob.bin"
    f.write_bytes(payload)
    assert sha256_file(f) == hashlib.sha256(payload).hexdigest()


def test_sha256_empty_file(tmp_path: Path) -> None:
    f = tmp_path / "empty"
    f.write_bytes(b"")
    assert sha256_file(f) == hashlib.sha256(b"").hexdigest()


def test_sha256_tiny_chunk_size_same_result(tmp_path: Path) -> None:
    payload = b"abcdefghij" * 1000
    f = tmp_path / "blob.bin"
    f.write_bytes(payload)
    assert sha256_file(f, chunk_size=7) == hashlib.sha256(payload).hexdigest()
