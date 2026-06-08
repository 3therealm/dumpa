"""The `dumpa rewrite` engine: enumerate, preview, and apply smali find-and-replace.

A pure module (no Typer, no config) so it is unit-testable without an apk. It operates
on the workspace's decoded `smali/` tree (the `apktool d` output), never the original
input, so every edit is reversible by re-decoding. Smali files are small per-class, so
each target file is read whole — the streaming concern that drives `core.rules` applies
to `dump.cs`, which is not a rewrite target.

Flow: ``rewrite_rules_from_bundle`` turns a TOML bundle's ``kind="rewrite"`` rules into
compiled :class:`RewriteRule`s; ``plan_edits`` enumerates every match into an indexed,
deterministic :class:`RewritePlan`; ``apply_edits`` writes the selected substitutions
back to the smali tree.
"""

from __future__ import annotations

import itertools
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from dumpa.core.errors import ConfigError, DumpaError
from dumpa.core.report import Confidence
from dumpa.core.rules import RuleBundle

logger = logging.getLogger("dumpa")

const_default_rewrite_target = "**/*.smali"
const_max_rewrite_file_bytes = 512 << 20    # skip a pathological smali file rather than OOM

# Smali is ASCII/UTF-8; we read and write as raw bytes via latin-1 so a round-trip is
# byte-exact regardless of any stray non-ASCII bytes in a string literal.
_ENC = "latin-1"


@dataclass(frozen=True)
class RewriteRule:
    """One compiled regex from a ``kind="rewrite"`` rule, plus its replacement template."""
    subject: str
    category: str
    confidence: Confidence
    pattern: re.Pattern[bytes]
    source: str                 # the regex source, for diagnostics
    replace: bytes | None       # expand template; None in match-only (--pattern) mode
    targets: tuple[str, ...]


@dataclass(frozen=True)
class Match:
    """One match of a rewrite rule, with a stable 1-based index for selection."""
    index: int
    rule_subject: str
    category: str
    confidence: Confidence
    file_rel: str
    byte_offset: int
    line: int
    col: int                    # 1-based char column within the line
    before: str
    after: str | None           # None in match-only mode
    context: str                # the full source line, for preview
    line_match_count: int       # matches on this line; >1 -> locator disambiguates with @col

    @property
    def locator(self) -> str:
        """`file:line` for a lone match on the line, `file:line@col` when the line has more."""
        if self.line_match_count > 1:
            return f"{self.file_rel}:{self.line}@{self.col}"
        return f"{self.file_rel}:{self.line}"


@dataclass(frozen=True)
class RewritePlan:
    """Every match found, in deterministic order, plus any warnings raised while planning."""
    matches: tuple[Match, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class AppliedEdit:
    """A match that was actually written to disk."""
    match: Match
    rule_version: str


def rewrite_rules_from_bundle(bundle: RuleBundle) -> list[RewriteRule]:
    """Compile a bundle's ``kind="rewrite"`` rules into RewriteRules (one per regex source).

    Non-rewrite rules are ignored. Raises ConfigError if the bundle defines no usable
    rewrite rule.
    """
    out: list[RewriteRule] = []
    for rule in bundle.rules:
        if rule.kind != "rewrite" or not rule.regex:
            continue
        targets = rule.targets or (const_default_rewrite_target,)
        replace = rule.replace.encode(_ENC) if rule.replace else None
        flags = re.IGNORECASE if rule.case_insensitive else 0
        category = rule.attributes.get("category", "")
        for source in rule.regex:
            out.append(RewriteRule(
                subject=rule.subject, category=category, confidence=rule.confidence,
                pattern=re.compile(source.encode(_ENC), flags), source=source,
                replace=replace, targets=targets,
            ))
    if not out:
        raise ConfigError(f"bundle {bundle.name!r} defines no kind='rewrite' rules")
    return out


def parse_selection(spec: str, count: int) -> set[int]:
    """Parse a ``--select`` spec into a set of 1-based indices.

    ``all`` -> every index; otherwise a comma list of integers and ``lo-hi`` ranges over
    the previewed order. Out-of-range indices and reversed ranges raise ConfigError.
    """
    spec = spec.strip()
    if spec == "all":
        return set(range(1, count + 1))
    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo_s, _, hi_s = part.partition("-")
                lo, hi = int(lo_s), int(hi_s)
                if lo > hi:
                    raise ConfigError(f"--select: reversed range {part!r}")
                out.update(range(lo, hi + 1))
            else:
                out.add(int(part))
        except ValueError as e:
            raise ConfigError(f"--select: invalid token {part!r}") from e
    for idx in out:
        if idx < 1 or idx > count:
            raise ConfigError(f"--select: index {idx} out of range (1..{count})")
    return out


def _target_files(smali_dir: Path, targets: tuple[str, ...]) -> list[Path]:
    """In-tree files matching a rule's target globs, deduplicated and sorted."""
    root = smali_dir.resolve()
    seen: set[Path] = set()
    files: list[Path] = []
    for glob in targets:
        for path in sorted(smali_dir.glob(glob)):
            if path.is_file() and path.resolve().is_relative_to(root) and path not in seen:
                seen.add(path)
                files.append(path)
    return files


def _read_target(path: Path, cache: dict[Path, bytes], warnings: list[str]) -> bytes | None:
    if path in cache:
        return cache[path]
    try:
        if path.stat().st_size > const_max_rewrite_file_bytes:
            warnings.append(f"skipped oversized {path.name}")
            return None
        data = path.read_bytes()
    except OSError:
        warnings.append(f"cannot read {path.name}")
        return None
    cache[path] = data
    return data


def _line_col(data: bytes, offset: int) -> tuple[int, int]:
    """1-based (line, column) of a byte offset within `data`."""
    line = data.count(b"\n", 0, offset) + 1
    col = offset - (data.rfind(b"\n", 0, offset) + 1) + 1
    return line, col


def _line_text(data: bytes, offset: int) -> str:
    start = data.rfind(b"\n", 0, offset) + 1
    end = data.find(b"\n", offset)
    if end == -1:
        end = len(data)
    return data[start:end].decode(_ENC)


def plan_edits(smali_dir: Path, rules: list[RewriteRule], *,
               categories: tuple[str, ...] = ()) -> RewritePlan:
    """Enumerate every match of `rules` over the smali tree into an indexed plan.

    `categories` (when non-empty) limits which rules run; the filter applies to both
    preview and apply, so indices never drift between them. Index order is deterministic:
    sorted by (file relpath, byte offset, rule order), 1-based.
    """
    selected = [r for r in rules if not categories or r.category in categories]
    warnings: list[str] = []
    cache: dict[Path, bytes] = {}
    # (file_rel, byte_offset, rule_idx, rule, before_bytes, after_str_or_None, data)
    raw: list[tuple[str, int, int, RewriteRule, bytes, str | None]] = []
    data_by_rel: dict[str, bytes] = {}
    for rule_idx, rule in enumerate(selected):
        for path in _target_files(smali_dir, rule.targets):
            data = _read_target(path, cache, warnings)
            if data is None:
                continue
            rel = path.relative_to(smali_dir).as_posix()
            data_by_rel[rel] = data
            for m in rule.pattern.finditer(data):
                before = m.group()
                after = m.expand(rule.replace).decode(_ENC) if rule.replace is not None else None
                raw.append((rel, m.start(), rule_idx, rule, before, after))

    raw.sort(key=lambda e: (e[0], e[1], e[2]))

    # Per-line match counts drive the short/long locator form.
    line_counts: dict[tuple[str, int], int] = defaultdict(int)
    prepared: list[tuple[str, int, int, RewriteRule, bytes, str | None, int, int]] = []
    for rel, offset, rule_idx, rule, before, after in raw:
        line, col = _line_col(data_by_rel[rel], offset)
        line_counts[(rel, line)] += 1
        prepared.append((rel, offset, rule_idx, rule, before, after, line, col))

    matches: list[Match] = []
    for index, (rel, offset, _ri, rule, before, after, line, col) in enumerate(prepared, start=1):
        matches.append(Match(
            index=index, rule_subject=rule.subject, category=rule.category,
            confidence=rule.confidence, file_rel=rel, byte_offset=offset,
            line=line, col=col, before=before.decode(_ENC), after=after,
            context=_line_text(data_by_rel[rel], offset),
            line_match_count=line_counts[(rel, line)],
        ))
    return RewritePlan(matches=tuple(matches), warnings=tuple(warnings))


def apply_edits(smali_dir: Path, plan: RewritePlan, selection: set[int],
                *, rule_version: str) -> list[AppliedEdit]:
    """Write the selected substitutions back to the smali tree.

    Substitutions in one file are applied right-to-left by offset so earlier offsets stay
    valid as replacement lengths change. Each selected match is re-verified at its offset
    before writing (guards against an edited-since-preview tree). Two selected matches that
    overlap in one file raise DumpaError and write nothing. A match-only plan (no `after`)
    cannot be applied.
    """
    chosen = [m for m in plan.matches if m.index in selection]
    by_file: dict[str, list[Match]] = defaultdict(list)
    for m in chosen:
        by_file[m.file_rel].append(m)

    edits: list[AppliedEdit] = []
    for rel, group in by_file.items():
        ordered = sorted(group, key=lambda m: m.byte_offset)
        for a, b in itertools.pairwise(ordered):
            if a.byte_offset + len(a.before.encode(_ENC)) > b.byte_offset:
                raise DumpaError(
                    f"selected edits {a.index} and {b.index} overlap in {rel}; "
                    f"choose one")
        path = smali_dir / rel
        data = path.read_bytes()
        for m in reversed(ordered):
            if m.after is None:
                raise DumpaError(
                    f"edit {m.index} has no replacement (use a --replace bundle)")
            before = m.before.encode(_ENC)
            start, end = m.byte_offset, m.byte_offset + len(before)
            if data[start:end] != before:
                raise DumpaError(
                    f"edit {m.index} no longer matches at {m.locator}; re-run the preview")
            data = data[:start] + m.after.encode(_ENC) + data[end:]
        path.write_bytes(data)
        for m in ordered:
            edits.append(AppliedEdit(match=m, rule_version=rule_version))
    return edits
