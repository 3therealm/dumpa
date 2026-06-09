"""Diff two analysis reports — what changed between two app builds.

Compares findings by (kind, subject), so "new tracker", "removed protection",
"changed engine", "new endpoint" all fall out of one generic per-kind set diff. Pure
and model-only; the command layer renders it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from dumpa.core.dumpcs_methods import method_set
from dumpa.core.report import Report
from dumpa.core.workspace import Workspace

# Cap names listed per group in rendered output; the model keeps the full lists.
const_diff_display_cap = 200
const_dump_cs = "dump.cs"


def _str_list() -> list[str]:
    return []


@dataclass(frozen=True)
class KindDelta:
    """Subjects added/removed for one finding kind between two reports."""
    kind: str
    added: list[str] = field(default_factory=_str_list)
    removed: list[str] = field(default_factory=_str_list)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


@dataclass(frozen=True)
class ReportDiff:
    """The difference between an old and a new report."""
    engine_before: str | None
    engine_after: str | None
    deltas: list[KindDelta]
    companies_added: list[str] = field(default_factory=_str_list)
    companies_removed: list[str] = field(default_factory=_str_list)

    @property
    def engine_changed(self) -> bool:
        return self.engine_before != self.engine_after

    @property
    def companies_changed(self) -> bool:
        return bool(self.companies_added or self.companies_removed)

    @property
    def changed(self) -> bool:
        return (self.engine_changed or self.companies_changed
                or any(d.changed for d in self.deltas))


def _owner_set(report: Report) -> set[str]:
    return {f.attributes["owner"] for f in report.findings
            if f.kind == "tracker" and f.attributes.get("owner")}


def diff_reports(old: Report, new: Report) -> ReportDiff:
    """Compute the per-kind subject diff between two reports."""
    kinds = sorted({f.kind for f in old.findings} | {f.kind for f in new.findings})
    deltas: list[KindDelta] = []
    for kind in kinds:
        old_subjects = {f.subject for f in old.findings if f.kind == kind}
        new_subjects = {f.subject for f in new.findings if f.kind == kind}
        added = sorted(new_subjects - old_subjects)
        removed = sorted(old_subjects - new_subjects)
        if added or removed:
            deltas.append(KindDelta(kind=kind, added=added, removed=removed))
    old_owners = _owner_set(old)
    new_owners = _owner_set(new)
    return ReportDiff(
        engine_before=old.facts.engine,
        engine_after=new.facts.engine,
        deltas=deltas,
        companies_added=sorted(new_owners - old_owners),
        companies_removed=sorted(old_owners - new_owners),
    )


def render_diff(old_label: str, new_label: str, diff: ReportDiff) -> str:
    """Render a diff as human-readable text."""
    lines = [f"diff {old_label} -> {new_label}", ""]
    if diff.engine_changed:
        lines.append(f"engine: {diff.engine_before or 'n/a'} -> {diff.engine_after or 'n/a'}")
        lines.append("")
    if diff.companies_changed:
        lines.append("## companies")
        for owner in diff.companies_added:
            lines.append(f"  + {owner}")
        for owner in diff.companies_removed:
            lines.append(f"  - {owner}")
        lines.append("")
    for delta in diff.deltas:
        lines.append(f"## {delta.kind}")
        for subject in delta.added:
            lines.append(f"  + {subject}")
        for subject in delta.removed:
            lines.append(f"  - {subject}")
        lines.append("")
    if not diff.changed:
        lines.append("no finding changes")
    return "\n".join(lines).rstrip() + "\n"


# --- native symbol diff ------------------------------------------------------


@dataclass(frozen=True)
class NativeSymbolDelta:
    """Exports/imports added or removed for one lib/<abi>/*.so between two workspaces."""
    lib: str                     # "<abi>/<name>.so"
    exports_added: list[str] = field(default_factory=_str_list)
    exports_removed: list[str] = field(default_factory=_str_list)
    imports_added: list[str] = field(default_factory=_str_list)
    imports_removed: list[str] = field(default_factory=_str_list)

    @property
    def changed(self) -> bool:
        return bool(self.exports_added or self.exports_removed
                    or self.imports_added or self.imports_removed)


def _load_sidecars(ws: Workspace) -> dict[str, dict[str, set[str]]]:
    """{ '<abi>/<lib>.so': {'exports': {...}, 'imports': {...}} } from dumps/native/*.json."""
    out: dict[str, dict[str, set[str]]] = {}
    native_dir = ws.native_dir
    if not native_dir.is_dir():
        return out
    for sidecar in sorted(native_dir.glob("*.json")):
        try:
            data = json.loads(sidecar.read_text(encoding="UTF-8"))
        except (OSError, ValueError):
            continue
        abi = data.get("abi", "")
        lib = data.get("lib", sidecar.stem)
        key = f"{abi}/{lib}" if abi else lib
        out[key] = {
            "exports": {s.get("name", "") for s in data.get("exports", []) if s.get("name")},
            "imports": {s.get("name", "") for s in data.get("imports", []) if s.get("name")},
        }
    return out


def diff_native_symbols(old_ws: Workspace, new_ws: Workspace) -> list[NativeSymbolDelta]:
    """Per-lib export/import set diff from each workspace's dumps/native/*.json sidecars.

    A lib present on only one side yields an all-added or all-removed delta. Only libs
    with a real change are returned, sorted by lib name.
    """
    old = _load_sidecars(old_ws)
    new = _load_sidecars(new_ws)
    deltas: list[NativeSymbolDelta] = []
    for lib in sorted(set(old) | set(new)):
        o = old.get(lib, {"exports": set(), "imports": set()})
        n = new.get(lib, {"exports": set(), "imports": set()})
        delta = NativeSymbolDelta(
            lib=lib,
            exports_added=sorted(n["exports"] - o["exports"]),
            exports_removed=sorted(o["exports"] - n["exports"]),
            imports_added=sorted(n["imports"] - o["imports"]),
            imports_removed=sorted(o["imports"] - n["imports"]),
        )
        if delta.changed:
            deltas.append(delta)
    return deltas


def _render_capped(lines: list[str], sign: str, names: list[str]) -> None:
    """Append up to the display cap of `  <sign> name` lines, with an overflow note."""
    for name in names[:const_diff_display_cap]:
        lines.append(f"    {sign} {name}")
    extra = len(names) - const_diff_display_cap
    if extra > 0:
        lines.append(f"    ... ({sign}{extra} more)")


def render_native_symbol_diff(deltas: list[NativeSymbolDelta]) -> str:
    """Render the native-symbol section; empty string when nothing changed."""
    if not deltas:
        return ""
    lines = ["## native symbols", ""]
    for d in deltas:
        lines.append(d.lib)
        lines.append(f"  exports +{len(d.exports_added)} / -{len(d.exports_removed)}")
        _render_capped(lines, "+", d.exports_added)
        _render_capped(lines, "-", d.exports_removed)
        lines.append(f"  imports +{len(d.imports_added)} / -{len(d.imports_removed)}")
        _render_capped(lines, "+", d.imports_added)
        _render_capped(lines, "-", d.imports_removed)
    lines.append("")
    return "\n".join(lines)


# --- Unity method (dump.cs) diff ---------------------------------------------


@dataclass(frozen=True)
class MethodDelta:
    """IL2CPP method signatures added/removed between two dump.cs files."""
    added: list[str] = field(default_factory=_str_list)
    removed: list[str] = field(default_factory=_str_list)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


def diff_unity_methods(old_ws: Workspace, new_ws: Workspace) -> MethodDelta | None:
    """Set-diff of dump.cs method signatures. None when either dump.cs is absent.

    Returning None (vs an empty delta) lets the caller print a "run analyze/dump-il2cpp
    first" note instead of implying the method sets are identical.
    """
    old_cs = old_ws.dumps_dir / const_dump_cs
    new_cs = new_ws.dumps_dir / const_dump_cs
    if not old_cs.is_file() or not new_cs.is_file():
        return None
    old = method_set(old_cs)
    new = method_set(new_cs)
    return MethodDelta(added=sorted(new - old), removed=sorted(old - new))


def render_unity_method_diff(delta: MethodDelta | None) -> str:
    """Render the unity-methods section (call only when the engine is Unity).

    `delta is None` means a dump.cs was missing on one/both sides -> a skip note. An
    unchanged delta renders nothing.
    """
    if delta is None:
        return "## unity methods\n  (no dump.cs in one or both inputs; run analyze first)\n"
    if not delta.changed:
        return ""
    lines = ["## unity methods",
             f"  +{len(delta.added)} / -{len(delta.removed)}"]
    _render_capped(lines, "+", delta.added)
    _render_capped(lines, "-", delta.removed)
    lines.append("")
    return "\n".join(lines)
