"""apksigner adapter: sign an APK and read back the verification output.

Passwords are referenced by environment-variable name and passed via apksigner's
`env:` form, so secrets never appear on the process command line.
"""

from __future__ import annotations

from pathlib import Path

from dumpa.core.process import run
from dumpa.core.tools import ResolvedTool


def sign(tool: ResolvedTool, apk: Path, *, keystore: Path, key_alias: str,
         keystore_password_env: str, key_password_env: str,
         min_sdk_version: int | None = None) -> None:
    """`apksigner sign` with v2+v3 schemes enabled."""
    cmd = tool.argv(
        'sign',
        '--ks', str(keystore),
        '--ks-pass', f'env:{keystore_password_env}',
        '--ks-key-alias', key_alias,
        '--key-pass', f'env:{key_password_env}',
        '--v2-signing-enabled', 'true',
        '--v3-signing-enabled', 'true',
    )
    if min_sdk_version is not None:
        cmd += ['--min-sdk-version', str(min_sdk_version)]
    cmd.append(str(apk))
    run(cmd, fail_msg='failed to sign apk file')


def verify(tool: ResolvedTool, apk: Path, timeout: int) -> str:
    """`apksigner verify --verbose --print-certs`; return its stdout for the caller to parse."""
    proc = run(tool.argv('verify', '--verbose', '--print-certs', str(apk)),
               fail_msg='apksigner verify failed', timeout=timeout, capture_stdout=True)
    return proc.stdout or ''
