"""Filesystem and OS helpers: tmp workspaces, hardlink-or-copy, platform checks."""

from __future__ import annotations

import errno
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, cast

logger = logging.getLogger("dumpa")

const_dir_tmp = ".dumpa"

# OS errors worth retrying: resource exhaustion under heavy parallel load (too many open
# files / process-wide fd table full / out of memory) and interrupted syscalls. A read that
# fails with one of these on a file that still exists is not a "missing file" — retrying
# turns a load-induced fault into a correct read instead of a silently dropped scan target.
# (Mid-read EINTR is already auto-retried by CPython per PEP 475; EMFILE/ENFILE strike at
# open() time, which is the case this guards.)
_TRANSIENT_ERRNOS = frozenset({
    errno.EMFILE, errno.ENFILE, errno.ENOMEM, errno.EINTR, errno.EAGAIN,
})
_RETRY_ATTEMPTS = 3
_RETRY_BASE_DELAY = 0.05


def is_transient_oserror(exc: OSError) -> bool:
    """True for OS errors worth retrying (resource exhaustion / interrupted syscall)."""
    return exc.errno in _TRANSIENT_ERRNOS


def retry_on_transient[T](fn: Callable[[], T], *, attempts: int = _RETRY_ATTEMPTS,
                          base_delay: float = _RETRY_BASE_DELAY) -> T:
    """Call `fn`, retrying transient OS errors with a short linear backoff.

    Re-raises a non-transient OSError immediately (e.g. ENOENT/EACCES — retrying would not
    help) and re-raises the last transient error once `attempts` are exhausted. Lets a caller
    recover from a load-induced EMFILE/ENFILE fault instead of treating it as a permanent
    failure and silently dropping the file.
    """
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except OSError as exc:
            if attempt >= attempts or not is_transient_oserror(exc):
                raise
            err_no = exc.errno
            err_name = errno.errorcode.get(err_no, err_no) if err_no is not None else "unknown"
            logger.debug("transient OS error (%s), retry %d/%d",
                         err_name, attempt, attempts)
            time.sleep(base_delay * attempt)
    raise AssertionError("unreachable")  # loop returns or raises on the last attempt


@contextmanager
def open_resilient(path: Path, mode: str = "rb") -> Generator[BinaryIO]:
    """Open `path`, retrying a transient OS error at open() time, and always close it.

    The open is the point a load-induced EMFILE/ENFILE strikes (no free fd to hand out), so
    retrying just the open recovers the common case without re-running any partial read.
    Non-transient errors (missing file, permission) propagate to the caller unchanged.
    """
    handle = retry_on_transient(lambda: cast(BinaryIO, path.open(mode)))
    try:
        yield handle
    finally:
        handle.close()


def read_bytes_resilient(path: Path) -> bytes:
    """Read a whole file, retrying a transient OS error at open() time (see `open_resilient`)."""
    with open_resilient(path) as f:
        return f.read()


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


def link_or_copy(src: Any, dst: Any, *, follow_symlinks: bool = True) -> None:
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
