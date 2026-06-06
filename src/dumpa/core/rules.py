"""TOML rule bundles and the matching engine.

A rule bundle is a versioned, provenance-stamped TOML file describing detections.
Each rule fires into the shared `Finding` model, so detection logic is data, not
code, and every bundle is reproducible (name + version + source + updated date are
recorded). Parsing reuses stdlib `tomllib` — the same stack as `core.config`.

Phase 3 implements **path-glob** matchers: a rule matches when files in the
workspace's `extracted/` tree match its globs. That is enough for data-driven game
engine detection (libraries, assets, file layout). String / native-symbol / byte /
`dump.cs` matcher kinds are intentionally not implemented yet — they need the
scanners that arrive in later phases.

Bundle TOML shape::

    [bundle]
    name = "engines"
    version = "2026.06.1"
    source = "dumpa built-in"
    updated = "2026-06-06"

    [[rule]]
    kind = "engine"
    subject = "Unity"
    confidence = "high"
    match = "any"            # any (default) | all
    globs = ["lib/*/libil2cpp.so", "lib/*/libunity.so"]
"""

from __future__ import annotations

import importlib.resources
import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, cast

from dumpa.core.errors import ConfigError
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location

logger = logging.getLogger("dumpa")

const_rules_package = "dumpa.rules"
const_match_any = "any"
const_match_all = "all"
_MATCH_MODES = (const_match_any, const_match_all)
# Cap locations per rule so a glob over a huge asset tree can't bloat the report.
const_max_locations_per_rule = 10
# Files a content rule scans when it does not name its own targets: dex (class
# paths), native libs, manifest, and the resource table (domains/strings).
const_default_content_targets = ("**/*.dex", "lib/**/*.so", "AndroidManifest.xml", "resources.arsc")
const_content_chunk_size = 1 << 20          # 1 MiB streaming reads (never load whole-file)
const_max_content_scan_bytes = 512 << 20    # skip individual files larger than 512 MiB


def _empty_attrs() -> dict[str, str]:
    return {}


@dataclass(frozen=True)
class Rule:
    """One detection rule -> a Finding.

    A rule is either a *path* rule (``globs`` over the extracted tree) or a *content*
    rule (``strings`` searched inside ``targets`` files), never both. Content rules may
    carry tracker metadata (``attributes``: category / owner / purpose).
    """
    kind: str
    subject: str
    confidence: Confidence
    globs: tuple[str, ...] = ()
    strings: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    match: str = const_match_any
    state: FindingState = FindingState.PRESENT
    attributes: dict[str, str] = field(default_factory=_empty_attrs)

    @property
    def is_content(self) -> bool:
        return bool(self.strings)


@dataclass(frozen=True)
class RuleBundle:
    """A versioned, provenance-stamped collection of rules."""
    name: str
    version: str
    source: str
    updated: str
    rules: tuple[Rule, ...]


def _require_str(table: dict[str, Any], key: str, ctx: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{ctx}: missing or non-string '{key}'")
    return value


def _validate_glob(pattern: str, ctx: str) -> str:
    parts = pattern.split("/")
    if (
        "\\" in pattern
        or "\x00" in pattern
        or PurePosixPath(pattern).is_absolute()
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise ConfigError(f"{ctx}: unsafe glob {pattern!r}")
    return pattern


def _parse_globs(raw: object, ctx: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise ConfigError(f"{ctx}: 'globs' must be a non-empty list of strings")
    raw_items = cast("list[object]", raw)
    if not raw_items:
        raise ConfigError(f"{ctx}: 'globs' must be a non-empty list of strings")

    globs: list[str] = []
    for item in raw_items:
        if not isinstance(item, str) or not item:
            raise ConfigError(f"{ctx}: 'globs' must be a non-empty list of strings")
        globs.append(_validate_glob(item, ctx))
    return tuple(globs)


def _parse_str_list(raw: object, key: str, ctx: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise ConfigError(f"{ctx}: '{key}' must be a non-empty list of strings")
    raw_items = cast("list[object]", raw)
    if not raw_items:
        raise ConfigError(f"{ctx}: '{key}' must be a non-empty list of strings")

    values: list[str] = []
    for item in raw_items:
        if not isinstance(item, str) or not item:
            raise ConfigError(f"{ctx}: '{key}' must be a non-empty list of strings")
        values.append(item)
    return tuple(values)


def _parse_attributes(table: dict[str, Any], ctx: str) -> dict[str, str]:
    """Collect optional tracker metadata (category/owner/purpose) into a string map."""
    attrs: dict[str, str] = {}
    for key in ("category", "owner", "purpose"):
        value = table.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{ctx}: '{key}' must be a non-empty string")
        attrs[key] = value
    return attrs


def _parse_rule(raw: object, index: int) -> Rule:
    if not isinstance(raw, dict):
        raise ConfigError(f"rule #{index}: must be a table")
    table = cast("dict[str, Any]", raw)
    ctx = f"rule #{index}"
    kind = _require_str(table, "kind", ctx)
    subject = _require_str(table, "subject", ctx)
    conf_raw = _require_str(table, "confidence", ctx)
    try:
        confidence = Confidence(conf_raw)
    except ValueError as e:
        raise ConfigError(f"{ctx}: invalid confidence {conf_raw!r}") from e

    has_globs = "globs" in table
    has_strings = "strings" in table
    if has_globs == has_strings:
        raise ConfigError(f"{ctx}: a rule needs exactly one of 'globs' or 'strings'")

    globs: tuple[str, ...] = ()
    strings: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    if has_globs:
        globs = _parse_globs(table.get("globs"), ctx)
    else:
        strings = _parse_str_list(table.get("strings"), "strings", ctx)
        if "targets" in table:
            targets = tuple(_validate_glob(g, ctx) for g in _parse_str_list(table.get("targets"), "targets", ctx))

    match = table.get("match", const_match_any)
    if match not in _MATCH_MODES:
        raise ConfigError(f"{ctx}: 'match' must be one of {_MATCH_MODES}")

    state_raw = table.get("state", FindingState.PRESENT.value)
    try:
        state = FindingState(state_raw)
    except ValueError as e:
        raise ConfigError(f"{ctx}: invalid state {state_raw!r}") from e

    return Rule(
        kind=kind, subject=subject, confidence=confidence,
        globs=globs, strings=strings, targets=targets, match=match,
        state=state, attributes=_parse_attributes(table, ctx),
    )


def _parse_bundle(data: dict[str, Any], *, default_source: str) -> RuleBundle:
    bundle_tbl = data.get("bundle")
    if not isinstance(bundle_tbl, dict):
        raise ConfigError("rule bundle: missing [bundle] table")
    bundle_tbl = cast("dict[str, Any]", bundle_tbl)
    name = _require_str(bundle_tbl, "name", "[bundle]")
    version = _require_str(bundle_tbl, "version", "[bundle]")
    source = bundle_tbl.get("source") if isinstance(bundle_tbl.get("source"), str) else default_source
    updated = _require_str(bundle_tbl, "updated", "[bundle]")

    rules_raw = data.get("rule", [])
    if not isinstance(rules_raw, list):
        raise ConfigError("rule bundle: [[rule]] must be an array of tables")
    rules = tuple(_parse_rule(r, i) for i, r in enumerate(cast("list[object]", rules_raw)))
    if not rules:
        raise ConfigError(f"rule bundle {name!r}: no rules defined")

    return RuleBundle(name=name, version=version, source=str(source), updated=updated, rules=rules)


def load_bundle(path: Path) -> RuleBundle:
    """Load and validate a rule bundle from a TOML file on disk."""
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"failed to read rule bundle {path}: {e}") from e
    return _parse_bundle(data, default_source=str(path))


def builtin_bundle_names() -> list[str]:
    """List the names of bundles shipped inside the dumpa.rules package."""
    root = importlib.resources.files(const_rules_package)
    return sorted(
        entry.name[:-5] for entry in root.iterdir()
        if entry.name.endswith(".toml")
    )


def load_builtin(name: str) -> RuleBundle:
    """Load a bundle shipped inside the package (e.g. 'engines')."""
    resource = importlib.resources.files(const_rules_package) / f"{name}.toml"
    if not resource.is_file():
        available = ", ".join(builtin_bundle_names()) or "none"
        raise ConfigError(f"no built-in rule bundle {name!r} (available: {available})")
    with resource.open("rb") as f:
        data = tomllib.load(f)
    return _parse_bundle(data, default_source=f"builtin:{name}")


def _rule_matches(rule: Rule, extracted_dir: Path) -> dict[str, list[Path]]:
    """Return {glob: matched paths} for the globs that hit; empty if the rule did not fire."""
    matched: dict[str, list[Path]] = {}
    extracted_root = extracted_dir.resolve()
    for glob in rule.globs:
        hits = sorted(
            p for p in extracted_dir.glob(glob)
            if p.resolve().is_relative_to(extracted_root)
        )
        if hits:
            matched[glob] = hits
    fired = (len(matched) == len(rule.globs)) if rule.match == const_match_all else bool(matched)
    return matched if fired else {}


def _path_finding(rule: Rule, bundle: RuleBundle, matched: dict[str, list[Path]],
                  extracted_dir: Path) -> Finding:
    evidence: list[Evidence] = []
    locations: list[Location] = []
    for glob, hits in matched.items():
        first_rel = hits[0].relative_to(extracted_dir).as_posix()
        evidence.append(Evidence(
            description=f"matched glob '{glob}'",
            snippet=first_rel, tool="rules", rule_version=bundle.version,
        ))
        for hit in hits:
            if len(locations) >= const_max_locations_per_rule:
                break
            locations.append(Location(file_path=hit.relative_to(extracted_dir).as_posix()))
    return Finding(
        kind=rule.kind, subject=rule.subject, confidence=rule.confidence,
        state=rule.state, attributes=dict(rule.attributes),
        evidence=evidence, locations=locations,
    )


def _content_targets(extracted_dir: Path, targets: tuple[str, ...]) -> list[Path]:
    """Resolve content-scan target globs to a deduplicated, in-tree list of files."""
    root = extracted_dir.resolve()
    seen: set[Path] = set()
    files: list[Path] = []
    for glob in targets:
        for path in sorted(extracted_dir.glob(glob)):
            if path.is_file() and path.resolve().is_relative_to(root) and path not in seen:
                seen.add(path)
                files.append(path)
    return files


def _scan_for_patterns(files: list[Path], patterns: dict[str, bytes],
                       extracted_dir: Path) -> dict[str, tuple[str, int]]:
    """First-hit (relpath, byte offset) for each pattern across files; streams with overlap."""
    remaining = dict(patterns)            # key -> needle bytes
    found: dict[str, tuple[str, int]] = {}
    overlap = max((len(p) for p in patterns.values()), default=1) - 1
    for path in files:
        if not remaining:
            break
        try:
            if path.stat().st_size > const_max_content_scan_bytes:
                logger.debug("content scan: skipping oversized %s", path)
                continue
            rel = path.relative_to(extracted_dir).as_posix()
            with path.open("rb") as f:
                tail = b""
                base = 0  # absolute offset of the first byte of `chunk`
                while True:
                    chunk = f.read(const_content_chunk_size)
                    if not chunk:
                        break
                    window = tail + chunk
                    window_start = base - len(tail)
                    for key in [k for k in remaining if remaining[k] in window]:
                        found[key] = (rel, window_start + window.find(remaining[key]))
                        del remaining[key]
                    if not remaining:
                        break
                    base += len(chunk)
                    tail = window[-overlap:] if overlap > 0 else b""
        except OSError:
            logger.debug("content scan: cannot read %s", path, exc_info=True)
            continue
    return found


def _content_finding(rule: Rule, bundle: RuleBundle,
                     hits: dict[str, tuple[str, int]]) -> Finding:
    evidence: list[Evidence] = []
    locations: list[Location] = []
    for needle in rule.strings:
        if needle not in hits:
            continue
        rel, offset = hits[needle]
        evidence.append(Evidence(
            description=f"string '{needle}' found in {rel}",
            snippet=needle, tool="rules", rule_version=bundle.version,
        ))
        if len(locations) < const_max_locations_per_rule:
            locations.append(Location(file_path=rel, file_offset=offset))
    return Finding(
        kind=rule.kind, subject=rule.subject, confidence=rule.confidence,
        state=rule.state, attributes=dict(rule.attributes),
        evidence=evidence, locations=locations,
    )


def _apply_content_rules(rules: list[Rule], bundle: RuleBundle,
                         extracted_dir: Path) -> list[Finding]:
    """Scan each target-set once for all its rules' strings, then assemble findings."""
    by_targets: dict[tuple[str, ...], list[Rule]] = {}
    for rule in rules:
        by_targets.setdefault(rule.targets or const_default_content_targets, []).append(rule)

    findings: list[Finding] = []
    for targets, group in by_targets.items():
        patterns = {needle: needle.encode() for rule in group for needle in rule.strings}
        hits = _scan_for_patterns(_content_targets(extracted_dir, targets), patterns, extracted_dir)
        for rule in group:
            rule_hits = {s: hits[s] for s in rule.strings if s in hits}
            fired = (len(rule_hits) == len(rule.strings)) if rule.match == const_match_all else bool(rule_hits)
            if fired:
                findings.append(_content_finding(rule, bundle, rule_hits))
    return findings


def apply_bundle(bundle: RuleBundle, extracted_dir: Path) -> list[Finding]:
    """Run every rule in a bundle against an extracted apk tree; return the Findings."""
    findings: list[Finding] = []
    content_rules: list[Rule] = []
    for rule in bundle.rules:
        if rule.is_content:
            content_rules.append(rule)
            continue
        matched = _rule_matches(rule, extracted_dir)
        if matched:
            findings.append(_path_finding(rule, bundle, matched, extracted_dir))
    findings.extend(_apply_content_rules(content_rules, bundle, extracted_dir))
    return findings
