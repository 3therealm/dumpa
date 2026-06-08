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
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, cast

from dumpa.core.errors import ConfigError
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location

if TYPE_CHECKING:
    from dumpa.core.manifest import ManifestInfo

logger = logging.getLogger("dumpa")

const_rules_package = "dumpa.rules"
const_match_any = "any"
const_match_all = "all"
_MATCH_MODES = (const_match_any, const_match_all)
# Manifest matcher: which structured field a rule's patterns are tested against.
const_manifest_field_any = "any"
_MANIFEST_FIELDS = ("package", "permission", "component", "action", "category", const_manifest_field_any)
# Cap locations per rule so a glob over a huge asset tree can't bloat the report.
const_max_locations_per_rule = 10
# Files a content rule scans when it does not name its own targets: dex (class
# paths), native libs, manifest, and the resource table (domains/strings).
const_default_content_targets = ("**/*.dex", "lib/**/*.so", "AndroidManifest.xml", "resources.arsc")
const_content_chunk_size = 1 << 20          # 1 MiB streaming reads (never load whole-file)
const_max_content_scan_bytes = 512 << 20    # skip individual files larger than 512 MiB
const_regex_overlap = 1024                  # chunk overlap for regex matches near an edge
const_max_match_text = 200                  # cap a captured match (e.g. a secret) in evidence


def _empty_attrs() -> dict[str, str]:
    return {}


@dataclass(frozen=True)
class Rule:
    """One detection rule -> a Finding.

    A rule is a *path* rule (``globs`` over the extracted tree), a *content* rule
    (``strings``/``regex`` searched inside ``targets`` files), or a *manifest* rule
    (``manifest`` regexes tested against the parsed ``ManifestInfo``) — exactly one.
    Rules may carry tracker metadata (``attributes``: category / owner / purpose).
    """
    kind: str
    subject: str
    confidence: Confidence
    globs: tuple[str, ...] = ()
    strings: tuple[str, ...] = ()
    regex: tuple[str, ...] = ()
    manifest: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    domain_search: bool = False
    manifest_field: str = const_manifest_field_any
    targets: tuple[str, ...] = ()
    match: str = const_match_any
    state: FindingState = FindingState.PRESENT
    attributes: dict[str, str] = field(default_factory=_empty_attrs)
    case_insensitive: bool = False              # compile `regex` with re.IGNORECASE
    game_types: tuple[str, ...] = ()            # dumpcs category selectors; empty = always-on

    @property
    def is_content(self) -> bool:
        return bool(self.strings or self.regex or (self.domains and self.domain_search))

    @property
    def is_manifest(self) -> bool:
        return bool(self.manifest)

    @property
    def keys(self) -> tuple[str, ...]:
        """The pattern keys (literal strings, regex sources, or domain literals) matched on."""
        if self.domain_search:
            return self.domains
        return self.strings or self.regex


@dataclass(frozen=True)
class RuleBundle:
    """A versioned, provenance-stamped collection of rules."""
    name: str
    version: str
    source: str
    updated: str
    rules: tuple[Rule, ...]
    default_targets: tuple[str, ...] = ()   # content-scan targets for rules that omit their own

    def domain_rules(self) -> tuple[Rule, ...]:
        """Rules carrying `domains` (search or not), for the attribution table."""
        return tuple(r for r in self.rules if r.domains)


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


def _parse_domains(raw: object, ctx: str) -> tuple[str, ...]:
    """Parse + normalize a rule's `domains` list via the shared host validator.

    Each entry runs through core.domains.validate_host (raises ConfigError on
    scheme/path/'*'/edge-dots/empty-label/single-label/over-long-label).
    """
    from dumpa.core.domains import validate_host
    values = _parse_str_list(raw, "domains", ctx)
    return tuple(validate_host(v) for v in values)


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

    present = [k for k in ("globs", "strings", "regex", "manifest", "domains") if k in table]
    if len(present) != 1:
        raise ConfigError(
            f"{ctx}: a rule needs exactly one of 'globs', 'strings', 'regex', 'manifest', or 'domains'")
    if "domain_search" in table and "domains" not in table:
        raise ConfigError(f"{ctx}: 'domain_search' is only valid on a 'domains' rule")

    globs: tuple[str, ...] = ()
    strings: tuple[str, ...] = ()
    regex: tuple[str, ...] = ()
    manifest: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    domain_search = False
    manifest_field = const_manifest_field_any
    targets: tuple[str, ...] = ()
    if "globs" in table:
        globs = _parse_globs(table.get("globs"), ctx)
    elif "domains" in table:
        domains = _parse_domains(table.get("domains"), ctx)
        ds = table.get("domain_search", False)
        if not isinstance(ds, bool):
            raise ConfigError(f"{ctx}: 'domain_search' must be a boolean")
        domain_search = ds
        if "targets" in table:
            targets = tuple(
                _validate_glob(g, ctx)
                for g in _parse_str_list(table.get("targets"), "targets", ctx))
    elif "manifest" in table:
        manifest = _parse_str_list(table.get("manifest"), "manifest", ctx)
        for pattern in manifest:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ConfigError(f"{ctx}: invalid manifest regex {pattern!r}: {e}") from e
        manifest_field = table.get("manifest_field", const_manifest_field_any)
        if manifest_field not in _MANIFEST_FIELDS:
            raise ConfigError(f"{ctx}: 'manifest_field' must be one of {_MANIFEST_FIELDS}")
    else:
        if "strings" in table:
            strings = _parse_str_list(table.get("strings"), "strings", ctx)
        else:
            regex = _parse_str_list(table.get("regex"), "regex", ctx)
            for pattern in regex:
                try:
                    re.compile(pattern.encode())
                except re.error as e:
                    raise ConfigError(f"{ctx}: invalid regex {pattern!r}: {e}") from e
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

    ci = table.get("case_insensitive", False)
    if not isinstance(ci, bool):
        raise ConfigError(f"{ctx}: 'case_insensitive' must be a boolean")
    game_types = (_parse_str_list(table.get("game_types"), "game_types", ctx)
                  if "game_types" in table else ())

    return Rule(
        kind=kind, subject=subject, confidence=confidence,
        globs=globs, strings=strings, regex=regex, manifest=manifest,
        domains=domains, domain_search=domain_search,
        manifest_field=manifest_field, targets=targets, match=match,
        state=state, attributes=_parse_attributes(table, ctx),
        case_insensitive=ci, game_types=game_types,
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

    default_targets: tuple[str, ...] = ()
    if "default_targets" in bundle_tbl:
        default_targets = tuple(
            _validate_glob(g, "[bundle]")
            for g in _parse_str_list(bundle_tbl.get("default_targets"), "default_targets", "[bundle]")
        )

    rules_raw = data.get("rule", [])
    if not isinstance(rules_raw, list):
        raise ConfigError("rule bundle: [[rule]] must be an array of tables")
    rules = tuple(_parse_rule(r, i) for i, r in enumerate(cast("list[object]", rules_raw)))
    if not rules:
        raise ConfigError(f"rule bundle {name!r}: no rules defined")

    return RuleBundle(name=name, version=version, source=str(source), updated=updated,
                      rules=rules, default_targets=default_targets)


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


# A content hit: (relpath, byte offset, matched text). For a literal the text is the
# needle; for a regex it is the (capped) matched substring — e.g. the secret value.
_Hit = tuple[str, int, str]


def _record_regex_hit(found: dict[str, _Hit], pending_regex: set[str], key: str,
                      match: re.Match[bytes], rel: str, window_start: int) -> None:
    text = match.group()[:const_max_match_text].decode("latin-1")
    found[key] = (rel, window_start + match.start(), text)
    pending_regex.discard(key)


def _scan_content(files: list[Path], literals: dict[str, bytes],
                  regexes: dict[str, re.Pattern[bytes]], extracted_dir: Path) -> dict[str, _Hit]:
    """First-hit (relpath, offset, text) for each literal/regex key; streams with overlap."""
    found: dict[str, _Hit] = {}
    pending_literals = set(literals)
    pending_regex = set(regexes)
    overlap = max((len(v) for v in literals.values()), default=1)
    overlap = max(overlap - 1, const_regex_overlap if regexes else 0)

    for path in files:
        if not pending_literals and not pending_regex:
            break
        try:
            if path.stat().st_size > const_max_content_scan_bytes:
                logger.debug("content scan: skipping oversized %s", path)
                continue
            rel = path.relative_to(extracted_dir).as_posix()
            with path.open("rb") as f:
                tail = b""
                base = 0
                while True:
                    chunk = f.read(const_content_chunk_size)
                    if not chunk:
                        break
                    window = tail + chunk
                    window_start = base - len(tail)
                    for key in [k for k in pending_literals if literals[k] in window]:
                        found[key] = (rel, window_start + window.find(literals[key]),
                                      key)
                        pending_literals.discard(key)
                    for key in list(pending_regex):
                        m = regexes[key].search(window)
                        if m is not None:
                            if m.end() == len(window):
                                continue
                            _record_regex_hit(found, pending_regex, key, m, rel, window_start)
                    if not pending_literals and not pending_regex:
                        break
                    base += len(chunk)
                    tail = window[-overlap:] if overlap > 0 else b""
                if tail and pending_regex:
                    window_start = base - len(tail)
                    for key in list(pending_regex):
                        m = regexes[key].search(tail)
                        if m is not None:
                            _record_regex_hit(found, pending_regex, key, m, rel, window_start)
        except OSError:
            logger.debug("content scan: cannot read %s", path, exc_info=True)
            continue
    return found


def _content_finding(rule: Rule, bundle: RuleBundle, hits: dict[str, _Hit]) -> Finding:
    evidence: list[Evidence] = []
    locations: list[Location] = []
    is_regex = bool(rule.regex)
    for key in rule.keys:
        if key not in hits:
            continue
        rel, offset, text = hits[key]
        description = (f"pattern /{key}/ matched {text!r} in {rel}" if is_regex
                      else f"string '{key}' found in {rel}")
        evidence.append(Evidence(
            description=description, snippet=text, tool="rules", rule_version=bundle.version,
        ))
        if len(locations) < const_max_locations_per_rule:
            # For a domain-search rule the matched key IS the host; stamp it so the
            # attribution pass and tracker-only blocklists can see it.
            locations.append(Location(
                file_path=rel, file_offset=offset,
                domain=key if rule.domain_search else None,
            ))
    return Finding(
        kind=rule.kind, subject=rule.subject, confidence=rule.confidence,
        state=rule.state, attributes=dict(rule.attributes),
        evidence=evidence, locations=locations,
    )


def scan_content_rules(rules: list[Rule], bundle: RuleBundle, root: Path) -> list[Finding]:
    """Apply content rules rooted at `root`, returning their Findings.

    Public entry for scanners that scan a non-`extracted/` root — e.g. the dumpcs
    scanner streams regex bundles over `dump.cs`/`script.json` under `dumps/`. Reuses
    the same streaming primitive (`_scan_content`) as the extracted-tree path.
    """
    return _apply_content_rules(rules, bundle, root)


def _apply_content_rules(rules: list[Rule], bundle: RuleBundle,
                         root: Path) -> list[Finding]:
    """Scan each target-set once for all its rules' patterns, then assemble findings."""
    fallback = bundle.default_targets or const_default_content_targets
    by_targets: dict[tuple[str, ...], list[Rule]] = {}
    for rule in rules:
        by_targets.setdefault(rule.targets or fallback, []).append(rule)

    findings: list[Finding] = []
    for targets, group in by_targets.items():
        # Literal keys come from `strings` and, for domain-search rules, their `domains`.
        literals = {k: k.encode() for rule in group for k in rule.keys if not rule.regex}
        # Keyed by pattern source so _content_finding can look hits up via rule.keys;
        # per-rule case flag is folded into the compile (IGNORECASE for ported dumpcs rules).
        regexes = {p: re.compile(p.encode(), re.IGNORECASE if rule.case_insensitive else 0)
                   for rule in group for p in rule.regex}
        hits = _scan_content(_content_targets(root, targets), literals, regexes, root)
        for rule in group:
            rule_hits = {k: hits[k] for k in rule.keys if k in hits}
            fired = (len(rule_hits) == len(rule.keys)) if rule.match == const_match_all else bool(rule_hits)
            if fired:
                findings.append(_content_finding(rule, bundle, rule_hits))
    return findings


def _manifest_candidates(manifest: ManifestInfo, field_name: str) -> list[str]:
    """Strings a manifest rule's patterns are tested against, for the selected field."""
    package = [manifest.package] if manifest.package else []
    permissions = list(manifest.permissions)
    components = [c.name for c in manifest.components if c.name]
    actions = [a for c in manifest.components for f in c.intent_filters for a in f.actions]
    categories = [cat for c in manifest.components for f in c.intent_filters for cat in f.categories]
    by_field = {
        "package": package,
        "permission": permissions,
        "component": components,
        "action": actions,
        "category": categories,
    }
    if field_name == const_manifest_field_any:
        return package + permissions + components + actions + categories
    return by_field[field_name]


def _apply_manifest_rules(rules: list[Rule], bundle: RuleBundle,
                          manifest: ManifestInfo) -> list[Finding]:
    """Test each manifest rule's regexes against the parsed manifest; assemble findings."""
    findings: list[Finding] = []
    for rule in rules:
        candidates = _manifest_candidates(manifest, rule.manifest_field)
        hits: list[tuple[str, str]] = []        # (pattern, matched value)
        for pattern in rule.manifest:
            compiled = re.compile(pattern)
            value = next((c for c in candidates if compiled.search(c)), None)
            if value is not None:
                hits.append((pattern, value))
        fired = (len(hits) == len(rule.manifest)) if rule.match == const_match_all else bool(hits)
        if not fired:
            continue
        evidence: list[Evidence] = []
        locations: list[Location] = []
        for pattern, value in hits:
            evidence.append(Evidence(
                description=f"manifest {rule.manifest_field} /{pattern}/ matched {value!r}",
                snippet=value, tool="rules", rule_version=bundle.version,
            ))
            if len(locations) < const_max_locations_per_rule:
                locations.append(Location(manifest_entry=value))
        findings.append(Finding(
            kind=rule.kind, subject=rule.subject, confidence=rule.confidence,
            state=rule.state, attributes=dict(rule.attributes),
            evidence=evidence, locations=locations,
        ))
    return findings


def apply_bundle(bundle: RuleBundle, extracted_dir: Path,
                 manifest: ManifestInfo | None = None) -> list[Finding]:
    """Run every rule in a bundle against an extracted apk tree; return the Findings.

    ``manifest`` supplies the parsed AndroidManifest.xml for manifest-matcher rules. When
    a bundle has manifest rules and the caller passes None, it is parsed lazily from the
    extracted tree; bundles without manifest rules never touch it.
    """
    findings: list[Finding] = []
    content_rules: list[Rule] = []
    manifest_rules: list[Rule] = []
    for rule in bundle.rules:
        if rule.is_manifest:
            manifest_rules.append(rule)
            continue
        if rule.is_content:
            content_rules.append(rule)
            continue
        matched = _rule_matches(rule, extracted_dir)
        if matched:
            findings.append(_path_finding(rule, bundle, matched, extracted_dir))
    findings.extend(_apply_content_rules(content_rules, bundle, extracted_dir))
    if manifest_rules:
        if manifest is None:
            manifest = _lazy_manifest(extracted_dir)
        if manifest is not None:
            findings.extend(_apply_manifest_rules(manifest_rules, bundle, manifest))
    return findings


def _lazy_manifest(extracted_dir: Path) -> ManifestInfo | None:
    """Parse extracted/AndroidManifest.xml on demand for manifest-rule matching."""
    from dumpa.core.errors import AxmlError
    from dumpa.core.manifest import const_manifest_name, parse_manifest_bytes
    path = extracted_dir / const_manifest_name
    try:
        return parse_manifest_bytes(path.read_bytes())
    except (OSError, AxmlError):
        logger.debug("manifest rule: cannot parse %s", extracted_dir, exc_info=True)
        return None
