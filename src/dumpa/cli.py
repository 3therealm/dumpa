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
from dumpa.commands import decompile as decompile_cmd
from dumpa.commands import diff as diff_cmd
from dumpa.commands import doctor as doctor_cmd
from dumpa.commands import dump_il2cpp as dump_il2cpp_cmd
from dumpa.commands import export as export_cmd
from dumpa.commands import info as info_cmd
from dumpa.commands import load as load_cmd
from dumpa.commands import repack as repack_cmd
from dumpa.commands import rewrite as rewrite_cmd
from dumpa.commands import rules as rules_cmd
from dumpa.commands import unpack as unpack_cmd
from dumpa.commands import update_signatures as update_signatures_cmd
from dumpa.commands import xref as xref_cmd
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
    workspace: Path | None = typer.Option(
        None, "--workspace",
        help="Reusable workspace dir; a later analyze/dump-il2cpp reuses its extraction."),
    force: bool = typer.Option(
        False, "--force", help="Rebuild even if a matching workspace already exists."),
    signing: str | None = typer.Option(None, "--signing", help=_SIGNING_HELP),
) -> None:
    """Convert a split .xapk bundle into a single installable .apk."""
    run_command(lambda: convert_cmd.run_convert(
        xapk_file, signing=signing, workspace=workspace, force=force))


@app.command()
def unpack(
    input_file: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True,
        help="Path to the .apk or .xapk to unpack.",
    ),
    workspace: Path | None = typer.Option(
        None, "--workspace", help="Workspace directory (default: ./<stem>-workspace)."),
    force: bool = typer.Option(
        False, "--force", help="Rebuild even if a matching workspace already exists."),
    decode: bool = typer.Option(
        True, "--decode/--no-decode",
        help="Run apktool decode into smali/ (required for `dumpa repack`)."),
) -> None:
    """Extract an APK/XAPK into a workspace and decode it to an editable smali tree."""
    run_command(lambda: unpack_cmd.unpack(
        input_file, workspace=workspace, force=force, decode=decode))


@app.command()
def repack(
    workspace: Path = typer.Argument(
        ..., exists=True, file_okay=False, readable=True,
        help="Workspace directory produced by `dumpa unpack --decode`.",
    ),
    signing: str | None = typer.Option(None, "--signing", help=_SIGNING_HELP),
    out: Path | None = typer.Option(
        None, "--out", help="Output apk path (default: ./<workspace>-repacked.apk)."),
) -> None:
    """Rebuild a workspace's smali tree into an installable (optionally re-signed) apk."""
    run_command(lambda: repack_cmd.repack(workspace, signing=signing, out=out))


@app.command()
def rewrite(
    workspace: Path = typer.Argument(
        ..., exists=True, file_okay=False, readable=True,
        help="Workspace directory (smali tree auto-decoded if missing).",
    ),
    pattern: Path = typer.Option(
        ..., "--pattern", exists=True, dir_okay=False, readable=True,
        help="TOML bundle of kind='rewrite' rules to match (preview)."),
    replace: Path | None = typer.Option(
        None, "--replace", exists=True, dir_okay=False, readable=True,
        help="TOML bundle with `replace` templates; required to apply."),
    select: str | None = typer.Option(
        None, "--select", help="all | index list/ranges over the preview, e.g. 2,5 or 1-3,7."),
    category: list[str] = typer.Option(
        [], "--category", help="Limit to these rule categories (repeatable)."),
    rebuild: bool = typer.Option(
        False, "--rebuild", help="After applying, repack + re-sign into a patched apk."),
    signing: str | None = typer.Option(None, "--signing", help=_SIGNING_HELP),
    out: Path | None = typer.Option(
        None, "--out", help="Patched apk path for --rebuild (default: ./<workspace>-rewritten.apk)."),
) -> None:
    """Preview or apply TOML-driven find-and-replace over a workspace's smali tree."""
    run_command(lambda: rewrite_cmd.rewrite(
        workspace, pattern=pattern, replace=replace, select=select,
        category=tuple(category), rebuild=rebuild, signing=signing, out=out))


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
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Re-run all scanners instead of reusing cached findings."),
    no_dump: bool = typer.Option(
        False, "--no-dump", help="Skip auto-dumping il2cpp (dump.cs) during analysis."),
    no_network: bool = typer.Option(
        False, "--no-network", help="Disable the networked Play store genre lookup."),
    jadx: bool = typer.Option(
        False, "--jadx", help="Also run a full JADX decompile into <workspace>/decompiled (heavy; opt-in)."),
    xref: bool = typer.Option(
        False, "--xref", help="Also build the cross-reference index into <workspace>/dumps/xref.json."),
    signing: str | None = typer.Option(None, "--signing", help=_SIGNING_HELP),
) -> None:
    """Extract an APK/XAPK once into a reproducible workspace."""
    run_command(lambda: analyze_cmd.analyze(
        input_file, workspace=workspace, force=force, signing=signing,
        use_cache=not no_cache, no_dump=no_dump, no_network=no_network, jadx=jadx, xref=xref))


@app.command()
def decompile(
    apk_file: Path | None = typer.Argument(
        None, exists=True, dir_okay=False, readable=True,
        help="APK to decompile (optional when --workspace is populated).",
    ),
    target_class: str | None = typer.Option(
        None, "--class", help="Decompile a single class, e.g. com.foo.Bar (the cheap path)."),
    all_classes: bool = typer.Option(
        False, "--all", help="Decompile the whole APK (heavy; explicit opt-in)."),
    out: Path | None = typer.Option(
        None, "--out", help="Output dir (default: <workspace>/decompiled or <apk-stem>-decompiled)."),
    workspace: Path | None = typer.Option(
        None, "--workspace", help="Read app.apk from this workspace; write into it."),
) -> None:
    """Read-only JADX decompile of an APK (requires --class or --all)."""
    run_command(lambda: decompile_cmd.decompile(
        apk_file, target_class=target_class, all_classes=all_classes,
        out_dir=out, workspace=workspace))


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
    fmt: str = typer.Option(
        "json", "--format",
        help="Report format: json | md | html | hosts | adguard | nextdns | rethinkdns | "
             "trackercontrol | csv | domains-csv."),
    out: Path | None = typer.Option(
        None, "--out", help="Write to this file instead of stdout."),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Rebuild from a fresh scan instead of cached findings/report.json."),
    trackers_only: bool = typer.Option(
        False, "--trackers-only",
        help="Narrow blocklist formats to attributed tracker-owned domains "
             "(default: all endpoints; no effect on json/md/csv)."),
) -> None:
    """Render a workspace's report as JSON, Markdown, HTML, a domain blocklist, or CSV."""
    run_command(lambda: export_cmd.export(
        workspace, fmt=fmt, out=out, use_cache=not no_cache, trackers_only=trackers_only))


@app.command()
def evidence(
    workspace: Path = typer.Argument(
        ..., exists=True, file_okay=False, readable=True,
        help="Workspace directory produced by `dumpa analyze`.",
    ),
    out: Path | None = typer.Option(
        None, "--out", help="Output directory (default: <workspace>/evidence)."),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Rebuild from a fresh scan instead of cached findings/report.json."),
) -> None:
    """Write a portable evidence bundle (manifest + snippets + index) for a workspace."""
    run_command(lambda: export_cmd.evidence(workspace, out=out, use_cache=not no_cache))


@app.command()
def diff(
    old: Path = typer.Argument(..., exists=True, readable=True, help="Old .apk/.xapk or workspace dir."),
    new: Path = typer.Argument(..., exists=True, readable=True, help="New .apk/.xapk or workspace dir."),
) -> None:
    """Show what changed between two apps (trackers, protections, engine, ...)."""
    run_command(lambda: diff_cmd.diff(old, new))


@app.command()
def xref(
    workspace: Path = typer.Argument(
        ..., exists=True, readable=True, help="Workspace dir or .apk/.xapk."),
    entity: str | None = typer.Argument(
        None, help="Trace one entity (domain/class/string/symbol); omit to list correlations."),
    min_layers: int = typer.Option(
        2, "--min-layers", help="List entities spanning at least this many layers."),
    case_insensitive: bool = typer.Option(
        False, "--case-insensitive", help="Fold case when matching the queried entity."),
    json_: bool = typer.Option(False, "--json", help="Emit JSON instead of text."),
    out: Path | None = typer.Option(None, "--out", help="Write output to a file."),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Rebuild the index instead of reusing dumps/xref.json."),
) -> None:
    """Cross-reference an entity across manifest, smali, native, dump.cs, resources, assets."""
    run_command(lambda: xref_cmd.xref(
        workspace, entity=entity, min_layers=min_layers,
        case_insensitive=case_insensitive, json_=json_, out=out, use_cache=not no_cache))


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


@app.command(name="update-signatures")
def update_signatures(
    db: str = typer.Option(
        "exodus", "--db",
        help="Signature database: exodus | trackercontrol (trackers) | apkid (protections)."),
    source: str | None = typer.Option(
        None, "--source", help="Override the database URL (default: the DB's official endpoint)."),
    out: Path | None = typer.Option(
        None, "--out", dir_okay=False,
        help="Write the bundle here (default: the user rules dir; point at the in-repo "
             "bundle to regenerate the vendored snapshot)."),
) -> None:
    """Refresh an imported signature bundle from an upstream DB (explicit, networked).

    `apkid` writes the `protections_apkid` bundle; the others write `trackers_*`.
    """
    run_command(lambda: update_signatures_cmd.update_signatures(db=db, source=source, out=out))


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
def doctor(
    full: bool = typer.Option(
        False, "--full",
        help="Also report advisory environment checks (Python/Java/SDK, signing, rule bundles)."),
) -> None:
    """Check that required external tools (apktool, zipalign, ...) are installed."""
    run_command(lambda: doctor_cmd.doctor(full=full))


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
