"""apktool adapter: decode splits and repack the merged APK dir.

Owns apktool's argv quirks: the `--` sentinel against flag-injection via filenames,
the JVM heap lift, and the one-shot `--keep-broken-res` retry for splits that the
strict decode path rejects but aapt2 will still link after dummy-stripping.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from dumpa.core.errors import ConfigError, DumpaError, ToolExecutionError, ToolTimeoutError
from dumpa.core.process import run
from dumpa.core.tools import ResolvedTool

logger = logging.getLogger("dumpa")

const_env_jvm_heap = 'DUMPA_JVM_HEAP'  # `-Xmx` value for apktool JVMs; default 2048m


def _jvm_env() -> dict[str, str]:
    """Build extra-env dict that lifts apktool's JVM heap above the wrapper's 1G default."""
    heap = os.environ.get(const_env_jvm_heap, '2048m').strip() or '2048m'
    if not re.fullmatch(r'[1-9][0-9]*[kKmMgG]?', heap):
        raise ConfigError(f'{const_env_jvm_heap} must look like 2048m, 2g, or 1024')
    # `_JAVA_OPTIONS` is appended after command-line args, so it overrides the
    # `-Xmx1024M` set by the apktool bash wrapper.
    return {'_JAVA_OPTIONS': f'-Xmx{heap}'}


def decode(tool: ResolvedTool, apk_file: str, cwd: Path, flags: tuple[str, ...]) -> None:
    """`apktool d` a single split into cwd with type-specific flags.

    On first failure, retries once with `-f --keep-broken-res`. A timeout is not
    retried (it re-raises) — only hard decode errors get the lenient second pass.
    """
    # `--` sentinel prevents a malicious split filename like `-Dfoo.apk` from being parsed as a flag.
    try:
        run(tool.argv('d', *flags, '--', apk_file), cwd=cwd,
            fail_msg=f'failed to unpack {apk_file}', extra_env=_jvm_env())
    except ToolTimeoutError:
        raise
    except ToolExecutionError:
        logger.warning("retry unpack with --keep-broken-res: %s", apk_file)
        run(tool.argv('d', *flags, '-f', '--keep-broken-res', '--', apk_file), cwd=cwd,
            fail_msg=f'failed to unpack {apk_file} (even with --keep-broken-res)',
            extra_env=_jvm_env())


def decode_apk(tool: ResolvedTool, apk: Path, out_dir: Path) -> None:
    """`apktool d -f -o <out_dir> -- <apk>` — full decode (smali + resources) of one apk.

    Unlike `decode` (cwd-relative, basename-named, for splits), this takes explicit apk
    and output paths so callers control the workspace layout. Same JVM heap lift and the
    one-shot `--keep-broken-res` retry on a hard decode failure (timeouts re-raise).
    """
    base = ('d', '-f', '-o', str(out_dir), '--', str(apk))
    try:
        run(tool.argv(*base), fail_msg=f'failed to decode {apk.name}', extra_env=_jvm_env())
    except ToolTimeoutError:
        raise
    except ToolExecutionError:
        logger.warning("retry decode with --keep-broken-res: %s", apk.name)
        run(tool.argv('d', '-f', '--keep-broken-res', '-o', str(out_dir), '--', str(apk)),
            fail_msg=f'failed to decode {apk.name} (even with --keep-broken-res)',
            extra_env=_jvm_env())


def build(tool: ResolvedTool, apk_dir: Path) -> Path:
    """`apktool b` the merged dir; return the built apk path under dist/."""
    run(tool.argv('b', '--', str(apk_dir)), cwd=apk_dir.parent,
        fail_msg=f'failed to pack {apk_dir.name}', extra_env=_jvm_env())
    built = apk_dir / 'dist' / f'{apk_dir.name}.apk'
    if not built.exists():
        raise DumpaError("result apk not found")
    return built
