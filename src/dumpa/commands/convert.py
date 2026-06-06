#!/usr/bin/python3
"""`dumpa convert` command entry: argv glue and profile wrapper.

The conversion pipeline lives in `dumpa.convert.*`; this module is the thin
command layer (legacy argv parsing, the cProfile wrapper, exception mapping via
run_command). `convert_xapk` is re-exported for back-compat.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from dumpa.commands.base import run_command
from dumpa.convert.models import const_env_profile, const_ext_xapk
from dumpa.convert.pipeline import convert_xapk
from dumpa.core.logging import configure_logging

__all__ = ["convert_xapk", "main", "run_convert"]

logger = logging.getLogger("dumpa")


# === CLI argument helpers (legacy argv entrypoint) ===

def print_help() -> None:
    """Print CLI usage."""
    sys.stdout.write(
        "\n"
        "Convert a split .xapk bundle into a single installable .apk.\n"
        "Usage: dumpa convert PATH_TO_FILE.xapk\n"
        "\n"
    )


def get_param_xapk_file_name() -> str:
    """Return the raw xapk argument from argv."""
    return sys.argv[1]


def get_param_xapk_abs_path() -> Path:
    """Return the absolute path to the input xapk."""
    return Path(get_param_xapk_file_name()).resolve()


def check_sys_args() -> bool:
    """Validate argv: exactly one .xapk path that exists."""
    if len(sys.argv) != 2:
        return False
    name = get_param_xapk_file_name()
    if not name.endswith(const_ext_xapk):
        return False
    return Path(name).resolve().is_file()


def _run_with_profile(profile_target: str, xapk_path: Path) -> None:
    """Run convert_xapk under cProfile; dump stats to file, print top 20 by cumtime."""
    import cProfile
    import pstats
    from pstats import SortKey

    profiler = cProfile.Profile()
    profiler.enable()
    try:
        convert_xapk(xapk_path)
    finally:
        profiler.disable()
        out_path = Path(profile_target if profile_target != '1' else '.dumpa-profile.prof').resolve()
        stats = pstats.Stats(profiler).sort_stats(SortKey.CUMULATIVE)
        stats.dump_stats(str(out_path))
        logger.info("profile written to %s", out_path)
        logger.info("top 20 by cumulative time:")
        stats.print_stats(20)


def run_convert(xapk_path: Path) -> None:
    """Run conversion, honoring the profile env var.

    Mapping exceptions to exit codes is the caller's responsibility (run_command).
    """
    profile_target = os.environ.get(const_env_profile, '').strip()
    if profile_target:
        _run_with_profile(profile_target, xapk_path)
    else:
        convert_xapk(xapk_path)


def main() -> None:
    """Legacy argv entrypoint: `python -m dumpa.commands.convert app.xapk`."""
    if not check_sys_args():
        print_help()
        sys.exit(-1)
    configure_logging()
    run_command(lambda: run_convert(get_param_xapk_abs_path()))


if __name__ == '__main__':
    main()
