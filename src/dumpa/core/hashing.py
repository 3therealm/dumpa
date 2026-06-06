"""Content hashing helpers.

The streamed digest is the reproducibility anchor for a workspace: it ties every
recorded finding to one exact input artifact without ever loading a multi-hundred-MB
file whole into memory.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

const_hash_chunk_size = 1 << 20  # 1 MiB


def sha256_file(path: Path, *, chunk_size: int = const_hash_chunk_size) -> str:
    """Return the hex SHA-256 of a file, read in bounded chunks (never whole-file)."""
    digest = hashlib.sha256()
    with path.open('rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()
