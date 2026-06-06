"""Filesystem and OS helpers: tmp workspaces, hardlink-or-copy, platform checks."""

from __future__ import annotations

import errno
import logging
import os
import platform
import shutil
import subprocess
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

logger = logging.getLogger("dumpa")

const_dir_tmp = ".dumpa"


def is_windows() -> bool:
    """Return True if running on Windows."""
    return platform.system() == "Windows"


def windows_hide_file(file_path: Path) -> None:
    """Set hidden attribute on a Windows path; return code ignored."""
    try:
        subprocess.run(
            ["attrib", "+h", str(file_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        logger.debug("failed to hide file on Windows: %s", file_path, exc_info=True)


def create_or_recreate_dir(dir_path: Path) -> None:
    """Wipe and recreate a directory (or replace a file at the same path)."""
    if dir_path.exists() or dir_path.is_symlink():
        if dir_path.is_dir() and not dir_path.is_symlink():
            shutil.rmtree(dir_path)
        else:
            dir_path.unlink()
    dir_path.mkdir()
    if is_windows():
        windows_hide_file(dir_path)


@contextmanager
def working_tmp_dir(parent: Path) -> Generator[Path]:
    """Create a private .dumpa.* tmp dir and clean it up on exit even when interrupted.

    Set DUMPA_KEEP_TMP=1 to retain the tmp dir after the run (debug aid).
    """
    tmp = Path(tempfile.mkdtemp(prefix=f'{const_dir_tmp}.', dir=str(parent))).resolve()
    keep = os.environ.get('DUMPA_KEEP_TMP', '') == '1'
    if is_windows():
        windows_hide_file(tmp)
    try:
        yield tmp
    finally:
        if not keep and tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)
        elif keep:
            logger.info("tmp retained: %s", tmp)


def delete_file_if_exists(path_to_file: Path) -> None:
    """Remove a file if present; silent no-op otherwise."""
    if path_to_file.exists():
        path_to_file.unlink()


def _link_or_copy(src: Any, dst: Any, *, follow_symlinks: bool = True) -> None:
    """Hardlink src→dst when same FS; fall back to data copy on EXDEV/EPERM.

    Hardlinks are zero-copy: a 2nd dirent pointing at the same inode. Since the
    merge tmp dir lives on the same FS as the unpacked split dirs, near every
    merged file is link-able — slashing wall time on resource/asset-heavy splits.
    Safe here: split dirs are read-only after unpack and are wiped at run end.
    """
    src_str = str(src)
    dst_str = str(dst)
    try:
        os.link(src_str, dst_str)
    except OSError as e:
        if e.errno not in (errno.EXDEV, errno.EPERM):
            raise
        shutil.copy(src_str, dst_str, follow_symlinks=follow_symlinks)
