"""Root Typer application for the `dumpa` toolkit.

Thin presentation layer: a --debug-aware root callback configures logging, and each
command delegates its work through run_command(), which owns the exception-to-exit
mapping. No business logic lives here.
"""

from __future__ import annotations

from pathlib import Path

import typer

from dumpa.commands import analyze as analyze_cmd
from dumpa.commands import clean as clean_cmd
from dumpa.commands import convert as convert_cmd
from dumpa.commands import diff as diff_cmd
from dumpa.commands import doctor as doctor_cmd
from dumpa.commands import dump_il2cpp as dump_il2cpp_cmd
from dumpa.commands import export as export_cmd
from dumpa.commands import info as info_cmd
from dumpa.commands import load as load_cmd
from dumpa.commands import rules as rules_cmd
from dumpa.commands.base import run_command
from dumpa.core.logging import configure_logging

app = typer.Typer(
    name="dumpa",
    help="Unity/Android reverse-engineering toolkit.",
    no_args_is_help=True,
    add_completion=False,
)

_SIGNING_HELP = "Signing preset: auto (default) | unsigned | debug | custom."


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
    signing: str | None = typer.Option(None, "--signing", help=_SIGNING_HELP),
) -> None:
    """Convert a split .xapk bundle into a single installable .apk."""
    run_command(lambda: convert_cmd.run_convert(xapk_file, signing=signing))


@app.command()
def analyze(
    input_file: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True,
        help="Path to the .apk or .xapk to analyze.",
    ),
    workspace: Path | None = typer.Option(
        None, "--workspace", help="Workspace directory (default: ./<stem>-workspace)."),
    force: bool = typer.Option(
        False, "--force", help="Rebuild even if a matching workspace already exists."),
    signing: str | None = typer.Option(None, "--signing", help=_SIGNING_HELP),
) -> None:
    """Extract an APK/XAPK once into a reproducible workspace."""
    run_command(lambda: analyze_cmd.analyze(
        input_file, workspace=workspace, force=force, signing=signing))


@app.command()
def info(
    input_file: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True,
        help="Path to the .apk or .xapk to inspect.",
    ),
) -> None:
    """Print fast triage facts (package, version, ABIs, signer) without deep analysis."""
    run_command(lambda: info_cmd.info(input_file))


@app.command()
def export(
    workspace: Path = typer.Argument(
        ..., exists=True, file_okay=False, readable=True,
        help="Workspace directory produced by `dumpa analyze`.",
    ),
    fmt: str = typer.Option("json", "--format", help="Report format: json | md | hosts | adguard."),
    out: Path | None = typer.Option(
        None, "--out", help="Write to this file instead of stdout."),
) -> None:
    """Render a workspace's report as JSON, Markdown, or a domain blocklist."""
    run_command(lambda: export_cmd.export(workspace, fmt=fmt, out=out))


@app.command()
def diff(
    old: Path = typer.Argument(..., exists=True, readable=True, help="Old .apk/.xapk or workspace dir."),
    new: Path = typer.Argument(..., exists=True, readable=True, help="New .apk/.xapk or workspace dir."),
) -> None:
    """Show what changed between two apps (trackers, protections, engine, ...)."""
    run_command(lambda: diff_cmd.diff(old, new))


@app.command(name="load")
def load(
    directory: Path = typer.Argument(
        ..., exists=True, file_okay=False, readable=True,
        help="Directory of .apk/.xapk files to summarize.",
    ),
) -> None:
    """Analyze a directory of APK/XAPK files into one combined summary."""
    run_command(lambda: load_cmd.load(directory))


@app.command()
def clean(
    workspace: Path = typer.Argument(
        ..., exists=True, file_okay=False, help="Workspace directory to remove."),
) -> None:
    """Remove a dumpa workspace directory (refuses non-workspace dirs)."""
    run_command(lambda: clean_cmd.clean(workspace))


rules_app = typer.Typer(
    name="rules", help="Test, explain, and list detection rule bundles.", no_args_is_help=True)
app.add_typer(rules_app)


@rules_app.command("test")
def rules_test(
    target: Path = typer.Argument(
        ..., exists=True, readable=True,
        help="Workspace dir, extracted dir, or .apk to test rules against.",
    ),
    bundle: Path | None = typer.Option(
        None, "--bundle", exists=True, dir_okay=False, help="Custom rule bundle TOML."),
    builtin: str | None = typer.Option(
        None, "--builtin", help="Named built-in bundle (default: engines)."),
) -> None:
    """Apply a rule bundle to a target and print the findings."""
    run_command(lambda: rules_cmd.rules_test(target, bundle_path=bundle, builtin=builtin))


@rules_app.command("explain")
def rules_explain(
    subject: str = typer.Argument(..., help="Rule subject to explain, e.g. Unity."),
    bundle: Path | None = typer.Option(
        None, "--bundle", exists=True, dir_okay=False, help="Custom rule bundle TOML."),
    builtin: str | None = typer.Option(
        None, "--builtin", help="Named built-in bundle (default: engines)."),
) -> None:
    """Explain how a subject is detected (its matchers and provenance)."""
    run_command(lambda: rules_cmd.rules_explain(subject, bundle_path=bundle, builtin=builtin))


@rules_app.command("list")
def rules_list() -> None:
    """List the built-in rule bundles."""
    run_command(rules_cmd.rules_list)


@app.command()
def doctor() -> None:
    """Check that required external tools (apktool, zipalign, ...) are installed."""
    run_command(doctor_cmd.doctor)


@app.command(name="dump-il2cpp")
def dump_il2cpp(
    apk_file: Path | None = typer.Argument(
        None, exists=True, dir_okay=False, readable=True,
        help="APK from a Unity il2cpp build (optional when --workspace is populated).",
    ),
    engine: str | None = typer.Option(
        None, "--engine", help="il2cpp engine: 'dumper' or 'inspector' (default from config)."),
    arch: str | None = typer.Option(
        None, "--arch", help="ABI to dump, e.g. arm64-v8a (default: arm64-v8a if present, else first)."),
    out: Path | None = typer.Option(
        None, "--out", help="Output directory (default: <apk-stem>-il2cpp, or <workspace>/dumps)."),
    workspace: Path | None = typer.Option(
        None, "--workspace", help="Read the extracted apk from this workspace (no re-extract)."),
) -> None:
    """Dump il2cpp metadata (C# stubs, headers, scripts) from a Unity APK."""
    run_command(lambda: dump_il2cpp_cmd.dump_il2cpp(
        apk_file, engine=engine, arch=arch, out_dir=out, workspace=workspace))


if __name__ == "__main__":
    app()
