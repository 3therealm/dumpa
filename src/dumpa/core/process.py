"""Bounded subprocess execution: the single chokepoint for running external tools."""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import BinaryIO

from dumpa.core.env import env_positive_int
from dumpa.core.errors import ToolExecutionError, ToolTimeoutError
from dumpa.core.logging import format_command

logger = logging.getLogger("dumpa")

const_subprocess_capture_limit = 2 * 1024 * 1024
const_subprocess_tail_bytes = 64 * 1024
const_env_tool_timeout = 'DUMPA_TOOL_TIMEOUT_SECONDS'
const_default_tool_timeout = 1800


def _read_limited_output(file_obj: BinaryIO, limit: int) -> str:
    """Read up to limit bytes from the start of a temporary output file."""
    file_obj.flush()
    file_obj.seek(0, os.SEEK_END)
    size = file_obj.tell()
    file_obj.seek(0)
    data = file_obj.read(min(size, limit))
    text = data.decode(errors='replace')
    if size > limit:
        text += f'\n[truncated {size - limit} byte(s)]'
    return text


def _read_output_tail(file_obj: BinaryIO, *, max_bytes: int = const_subprocess_tail_bytes,
                      max_lines: int = 50) -> str:
    """Read a bounded tail from a temporary subprocess output file."""
    file_obj.flush()
    file_obj.seek(0, os.SEEK_END)
    size = file_obj.tell()
    file_obj.seek(max(0, size - max_bytes))
    text = file_obj.read().decode(errors='replace')
    return '\n'.join(text.splitlines()[-max_lines:])


def run(cmd: list[str],
        cwd: Path | None = None,
        fail_msg: str | None = None,
        extra_env: dict[str, str] | None = None,
        timeout: int | None = None,
        capture_stdout: bool = False,
        capture_stderr: bool = False,
        ) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with bounded runtime and bounded output retention."""
    env: dict[str, str] | None = None
    if extra_env:
        env = os.environ.copy()
        env.update(extra_env)
    resolved_timeout = timeout or env_positive_int(const_env_tool_timeout, const_default_tool_timeout)

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd) if cwd else None,
                env=env,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=resolved_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            stderr_tail = _read_output_tail(stderr_file)
            stdout_tail = _read_output_tail(stdout_file, max_lines=20)
            logger.error("command timed out after %ss: %s", resolved_timeout, format_command(cmd))
            if stderr_tail:
                logger.error("stderr tail:\n%s", stderr_tail)
            if stdout_tail:
                logger.error("stdout tail:\n%s", stdout_tail)
            raise ToolTimeoutError(fail_msg or f'command timed out: {cmd[0]}') from e
        except OSError as e:
            raise ToolExecutionError(fail_msg or f'failed to execute: {cmd[0]}') from e

        if proc.returncode != 0:
            stderr_tail = _read_output_tail(stderr_file)
            stdout_tail = _read_output_tail(stdout_file, max_lines=20)
            logger.error("command failed (rc=%s): %s", proc.returncode, format_command(cmd))
            if stderr_tail:
                logger.error("stderr tail:\n%s", stderr_tail)
            if stdout_tail:
                logger.error("stdout tail:\n%s", stdout_tail)
            raise ToolExecutionError(fail_msg or f'command failed: {cmd[0]}')

        stdout = _read_limited_output(stdout_file, const_subprocess_capture_limit) if capture_stdout else ''
        stderr = _read_limited_output(stderr_file, const_subprocess_capture_limit) if capture_stderr else ''
        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
