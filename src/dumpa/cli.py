"""Root Typer application for the `dumpa` toolkit.

Thin presentation layer: a --debug-aware root callback configures logging, and each
command delegates its work through run_command(), which owns the exception-to-exit
mapping. No business logic lives here.
"""

from __future__ import annotations

from pathlib import Path

import typer

from dumpa.commands import convert as convert_cmd
from dumpa.commands import doctor as doctor_cmd
from dumpa.commands import dump_il2cpp as dump_il2cpp_cmd
from dumpa.commands.base import run_command
from dumpa.core.logging import configure_logging

app = typer.Typer(
    name="dumpa",
    help="Unity/Android reverse-engineering toolkit.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def root(
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging and full tracebacks."),
) -> None:
    """Unity/Android reverse-engineering toolkit."""
    configure_logging(debug)


@app.command()
def convert(
    xapk_file: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True,
        help="Path to the .xapk file to convert.",
    ),
) -> None:
    """Convert a split .xapk bundle into a single installable .apk."""
    run_command(lambda: convert_cmd.run_convert(xapk_file))


@app.command()
def doctor() -> None:
    """Check that required external tools (apktool, zipalign, ...) are installed."""
    run_command(doctor_cmd.doctor)


@app.command(name="dump-il2cpp")
def dump_il2cpp(
    apk_file: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True,
        help="APK from a Unity il2cpp build.",
    ),
    engine: str | None = typer.Option(
        None, "--engine", help="il2cpp engine: 'dumper' or 'inspector' (default from config)."),
    arch: str | None = typer.Option(
        None, "--arch", help="ABI to dump, e.g. arm64-v8a (default: arm64-v8a if present, else first)."),
    out: Path | None = typer.Option(
        None, "--out", help="Output directory (default: <apk-stem>-il2cpp next to the apk)."),
) -> None:
    """Dump il2cpp metadata (C# stubs, headers, scripts) from a Unity APK."""
    run_command(lambda: dump_il2cpp_cmd.dump_il2cpp(apk_file, engine=engine, arch=arch, out_dir=out))


if __name__ == "__main__":
    app()
