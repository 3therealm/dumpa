"""apksigner adapter: sign an APK and read back the verification output.

Passwords are referenced by environment-variable name and passed via apksigner's
`env:` form, so secrets never appear on the process command line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from dumpa.core.process import run
from dumpa.core.tools import ResolvedTool

# apksigner labels the line "Signer #1 certificate SHA-256 digest:" on older builds
# and "V3.0 Signer: certificate SHA-256 digest:" once a v3 block is present; match both.
_CERT_SHA256_RE = re.compile(r'certificate SHA-256 digest:\s*([0-9a-fA-F]+)')
_SCHEME_RE = re.compile(r'Verified using (v\d) scheme[^:]*:\s*(true|false)', re.IGNORECASE)


@dataclass(frozen=True)
class SignerInfo:
    """Signer facts parsed from `apksigner verify --print-certs` output."""
    cert_sha256: str | None
    schemes: tuple[str, ...]   # the vN schemes that verified true, e.g. ('v2', 'v3')


def parse_verify_output(text: str) -> SignerInfo:
    """Parse apksigner verify output into a SignerInfo (pure; safe on empty/unsigned text)."""
    cert_match = _CERT_SHA256_RE.search(text)
    schemes = tuple(
        m.group(1).lower()
        for m in _SCHEME_RE.finditer(text)
        if m.group(2).lower() == 'true'
    )
    return SignerInfo(cert_sha256=cert_match.group(1) if cert_match else None, schemes=schemes)


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


def verify(tool: ResolvedTool, apk: Path, timeout: int, *, quiet: bool = False) -> str:
    """`apksigner verify --verbose --print-certs`; return its stdout for the caller to parse.

    `quiet=True` suppresses error-level logging for callers (e.g. `info`) that treat a
    non-zero exit — an unsigned apk — as a normal outcome rather than a failure.
    """
    proc = run(tool.argv('verify', '--verbose', '--print-certs', str(apk)),
               fail_msg='apksigner verify failed', timeout=timeout,
               capture_stdout=True, quiet=quiet)
    return proc.stdout or ''
