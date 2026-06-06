"""Safe ZIP extraction with traversal, symlink, duplicate, and size-bomb guards."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from zipfile import ZipFile

from dumpa.core.env import env_positive_int
from dumpa.core.errors import UnsafeArchiveError

const_env_max_xapk_entries = 'DUMPA_MAX_ZIP_ENTRIES'
const_default_max_xapk_entries = 10000
const_env_max_xapk_uncompressed = 'DUMPA_MAX_ZIP_UNCOMPRESSED_BYTES'
const_default_max_xapk_uncompressed = 8 * 1024 * 1024 * 1024
const_copy_chunk_size = 1024 * 1024

_ZIP_SYMLINK_MODE = 0o120000


def _zip_limits() -> tuple[int, int]:
    """Return configured (max_entries, max_uncompressed_bytes) limits."""
    return (
        env_positive_int(const_env_max_xapk_entries, const_default_max_xapk_entries),
        env_positive_int(const_env_max_xapk_uncompressed, const_default_max_xapk_uncompressed),
    )


def _is_relative_to(child: Path, parent: Path) -> bool:
    """Path.is_relative_to() without raising."""
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _safe_zip_member_path(name: str) -> PurePosixPath:
    """Validate a ZIP member name using ZIP's POSIX path semantics."""
    if not name or '\x00' in name or '\\' in name:
        raise UnsafeArchiveError(f"refusing to extract unsafe zip entry: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ('', '.', '..') for part in path.parts):
        raise UnsafeArchiveError(f"refusing to extract unsafe zip entry: {name!r}")
    return path


def safe_extract_zip(zip_path: Path, dest: Path) -> None:
    """Extract a zip into dest, rejecting traversal, symlinks, duplicates, and oversized archives.

    Python's ZipFile.extractall sanitizes `..` and absolute paths since 3.6.2 but
    will still create symlink entries on POSIX, which can escape the destination.
    """
    max_entries, max_uncompressed = _zip_limits()
    dest_resolved = dest.resolve()
    extracted_bytes = 0
    seen_targets: set[Path] = set()

    with ZipFile(zip_path, 'r') as zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            raise UnsafeArchiveError(f"refusing zip with {len(infos)} entries; limit is {max_entries}")

        for zinfo in infos:
            name = zinfo.filename
            member_path = _safe_zip_member_path(name)
            unix_mode = (zinfo.external_attr >> 16) & 0o170000
            if unix_mode == _ZIP_SYMLINK_MODE:
                raise UnsafeArchiveError(f"refusing to extract symlink zip entry: {name!r}")

            extracted_bytes += zinfo.file_size
            if extracted_bytes > max_uncompressed:
                raise UnsafeArchiveError(
                    f"refusing zip with {extracted_bytes} uncompressed byte(s); limit is {max_uncompressed}"
                )

            target = (dest_resolved / Path(*member_path.parts)).resolve()
            if not _is_relative_to(target, dest_resolved):
                raise UnsafeArchiveError(f"refusing to extract outside destination: {name!r}")
            if target in seen_targets:
                raise UnsafeArchiveError(f"refusing duplicate zip entry target: {name!r}")
            seen_targets.add(target)

            if zinfo.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(zinfo, 'r') as src, target.open('wb') as dst:
                while True:
                    chunk = src.read(const_copy_chunk_size)
                    if not chunk:
                        break
                    dst.write(chunk)
