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
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

from dumpa.core.errors import ConfigError
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location

const_rules_package = "dumpa.rules"
const_match_any = "any"
const_match_all = "all"
_MATCH_MODES = (const_match_any, const_match_all)
# Cap locations per rule so a glob over a huge asset tree can't bloat the report.
const_max_locations_per_rule = 10


@dataclass(frozen=True)
class Rule:
    """One detection rule: globs over the extracted tree -> a Finding."""
    kind: str
    subject: str
    confidence: Confidence
    globs: tuple[str, ...]
    match: str = const_match_any


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

    globs = _parse_globs(table.get("globs"), ctx)

    match = table.get("match", const_match_any)
    if match not in _MATCH_MODES:
        raise ConfigError(f"{ctx}: 'match' must be one of {_MATCH_MODES}")

    return Rule(kind=kind, subject=subject, confidence=confidence, globs=globs, match=match)


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


def apply_bundle(bundle: RuleBundle, extracted_dir: Path) -> list[Finding]:
    """Run every rule in a bundle against an extracted apk tree; return the Findings."""
    findings: list[Finding] = []
    for rule in bundle.rules:
        matched = _rule_matches(rule, extracted_dir)
        if not matched:
            continue
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
        findings.append(Finding(
            kind=rule.kind, subject=rule.subject, confidence=rule.confidence,
            state=FindingState.PRESENT, evidence=evidence, locations=locations,
        ))
    return findings
