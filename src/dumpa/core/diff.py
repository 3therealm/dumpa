"""Diff two analysis reports — what changed between two app builds.

Compares findings by (kind, subject), so "new tracker", "removed protection",
"changed engine", "new endpoint" all fall out of one generic per-kind set diff. Pure
and model-only; the command layer renders it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dumpa.core.report import Report


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

    @property
    def engine_changed(self) -> bool:
        return self.engine_before != self.engine_after

    @property
    def changed(self) -> bool:
        return self.engine_changed or any(d.changed for d in self.deltas)


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
    return ReportDiff(
        engine_before=old.facts.engine,
        engine_after=new.facts.engine,
        deltas=deltas,
    )


def render_diff(old_label: str, new_label: str, diff: ReportDiff) -> str:
    """Render a diff as human-readable text."""
    lines = [f"diff {old_label} -> {new_label}", ""]
    if diff.engine_changed:
        lines.append(f"engine: {diff.engine_before or 'n/a'} -> {diff.engine_after or 'n/a'}")
        lines.append("")
    if not diff.deltas:
        lines.append("no finding changes" if not diff.engine_changed else "")
        return "\n".join(lines).rstrip() + "\n"
    for delta in diff.deltas:
        lines.append(f"## {delta.kind}")
        for subject in delta.added:
            lines.append(f"  + {subject}")
        for subject in delta.removed:
            lines.append(f"  - {subject}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
