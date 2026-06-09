"""TOML rule bundles and the matching engine.

A rule bundle is a versioned, provenance-stamped TOML file describing detections.
Each rule fires into the shared `Finding` model, so detection logic is data, not
code, and every bundle is reproducible (name + version + source + updated date are
recorded). Parsing reuses stdlib `tomllib` — the same stack as `core.config`.

Matcher kinds: **path-glob** (`globs` over the extracted tree), **content**
(`strings`/`regex`/`hex` searched inside `targets` files), **manifest** (`manifest`
regexes over the parsed `ManifestInfo`), and **domains**. `hex` is a YARA-style byte
signature (two-hex-digit bytes + `??` wildcards) lowered to a bytes-regex and run
through the same streaming/prefilter engine as `regex`. The native-symbol-table
matcher is still deferred (the ELF parser already inventories symbols separately).

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
from collections.abc import Iterable
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
const_min_anchor_len = 3                    # shortest literal run usable as a regex prefilter anchor
const_rewrite_encoding = "latin-1"          # byte-exact smali rewrite matching/replacement
const_min_byte_anchor = 4                   # shortest fixed-byte run usable as a hex prefilter anchor
const_max_hex_pattern_bytes = const_regex_overlap   # a sig must fit within the chunk overlap


def _empty_attrs() -> dict[str, str]:
    return {}


def compile_hex(pattern: str) -> tuple[re.Pattern[bytes], list[bytes] | None]:
    """Lower a hex byte-pattern to (compiled bytes-regex, prefilter anchors).

    Grammar: whitespace-separated or contiguous 2-char tokens — a two-hex-digit byte
    or ``??`` (any byte). A fixed byte lowers to its escaped literal; ``??`` lowers to
    ``[\\x00-\\xff]``. Compiled with re.DOTALL so a wildcard also matches 0x0A.

    The anchor is the single longest run of consecutive fixed bytes (a hex pattern has
    no top-level alternation, so one suffices), returned as a one-element list to match
    ``_branch_anchors``' shape — or None when that run is shorter than
    ``const_min_byte_anchor`` (the pattern then always-runs: sound, just unfiltered).
    Any match must contain the fixed run verbatim, so the prefilter never skips a hit.

    Raises ConfigError on an empty, odd-length, non-hex, all-wildcard, or over-long
    pattern (one longer than ``const_max_hex_pattern_bytes`` could straddle the overlap).
    """
    compact = "".join(pattern.split())
    if not compact:
        raise ConfigError(f"hex pattern {pattern!r}: empty")
    if len(compact) % 2 != 0:
        raise ConfigError(f"hex pattern {pattern!r}: odd number of hex digits")
    tokens: list[int | None] = []
    for i in range(0, len(compact), 2):
        unit = compact[i:i + 2]
        if unit == "??":
            tokens.append(None)
            continue
        try:
            tokens.append(int(unit, 16))
        except ValueError as e:
            raise ConfigError(f"hex pattern {pattern!r}: invalid byte {unit!r}") from e
    if len(tokens) > const_max_hex_pattern_bytes:
        raise ConfigError(
            f"hex pattern {pattern!r}: {len(tokens)} bytes exceeds the "
            f"{const_max_hex_pattern_bytes}-byte limit")
    if all(t is None for t in tokens):
        raise ConfigError(f"hex pattern {pattern!r}: needs at least one fixed byte")

    parts = [re.escape(bytes([t])) if t is not None else b"[\x00-\xff]" for t in tokens]
    compiled = re.compile(b"".join(parts), re.DOTALL)

    best: list[int] = []
    cur: list[int] = []
    for t in tokens:
        if t is None:
            if len(cur) > len(best):
                best = cur
            cur = []
        else:
            cur.append(t)
    if len(cur) > len(best):
        best = cur
    anchors = [bytes(best)] if len(best) >= const_min_byte_anchor else None
    return compiled, anchors


@dataclass(frozen=True)
class Rule:
    """One detection rule -> a Finding.

    A rule is a *path* rule (``globs`` over the extracted tree), a *content* rule
    (``strings``/``regex`` searched inside ``targets`` files), or a *manifest* rule
    (``manifest`` regexes tested against the parsed ``ManifestInfo``) — exactly one.
    Rules may carry tracker metadata (``attributes``: category / owner / purpose /
    data_use, plus mediator / network on a mediation-adapter rule).
    """
    kind: str
    subject: str
    confidence: Confidence
    globs: tuple[str, ...] = ()
    strings: tuple[str, ...] = ()
    regex: tuple[str, ...] = ()
    bytes_hex: tuple[str, ...] = ()
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
    replace: str = ""                           # substitution template (kind="rewrite" only)

    @property
    def is_content(self) -> bool:
        return bool(self.strings or self.regex or self.bytes_hex
                    or (self.domains and self.domain_search))

    @property
    def is_manifest(self) -> bool:
        return bool(self.manifest)

    @property
    def keys(self) -> tuple[str, ...]:
        """The pattern keys (literal strings, regex sources, or domain literals) matched on."""
        if self.domain_search:
            return self.domains
        return self.strings or self.regex or self.bytes_hex


@dataclass(frozen=True)
class RuleBundle:
    """A versioned, provenance-stamped collection of rules."""
    name: str
    version: str
    source: str
    updated: str
    rules: tuple[Rule, ...]
    default_targets: tuple[str, ...] = ()   # content-scan targets for rules that omit their own
    license: str = ""                       # data license of an imported bundle (provenance)

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
    """Collect optional tracker metadata into a string map.

    `category`/`owner`/`purpose` describe a tracker; `data_use` is its likely data use
    (the Phase 5 SDK data-use mapping); `mediator`/`network` are the endpoints of a
    mediation-adapter edge (the Phase 5 ad-mediation graph).
    """
    attrs: dict[str, str] = {}
    for key in ("category", "owner", "purpose", "data_use", "mediator", "network"):
        value = table.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{ctx}: '{key}' must be a non-empty string")
        attrs[key] = value
    return attrs


def _validate_template(template: str, compiled: re.Pattern[bytes], ctx: str) -> None:
    """Reject a `replace` template that Python's replacement parser cannot apply.

    Validated at load (fail closed) so a bad backref or escape never surfaces mid-apply.
    """
    try:
        compiled.sub(template.encode(const_rewrite_encoding), b"", count=0)
    except UnicodeEncodeError as e:
        raise ConfigError(f"{ctx}: 'replace' must be encodable as {const_rewrite_encoding}") from e
    except re.error as e:
        raise ConfigError(f"{ctx}: invalid replace template: {e}") from e


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

    present = [k for k in ("globs", "strings", "regex", "hex", "manifest", "domains") if k in table]
    if len(present) != 1:
        raise ConfigError(
            f"{ctx}: a rule needs exactly one of "
            f"'globs', 'strings', 'regex', 'hex', 'manifest', or 'domains'")
    if "domain_search" in table and "domains" not in table:
        raise ConfigError(f"{ctx}: 'domain_search' is only valid on a 'domains' rule")

    globs: tuple[str, ...] = ()
    strings: tuple[str, ...] = ()
    regex: tuple[str, ...] = ()
    bytes_hex: tuple[str, ...] = ()
    manifest: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    domain_search = False
    manifest_field = const_manifest_field_any
    targets: tuple[str, ...] = ()
    compiled_regex: list[re.Pattern[bytes]] = []
    if "globs" in table:
        globs = _parse_globs(table.get("globs"), ctx)
    elif "hex" in table:
        bytes_hex = _parse_str_list(table.get("hex"), "hex", ctx)
        for pattern in bytes_hex:
            compile_hex(pattern)        # validate (fail closed); recompiled at scan time
        if "targets" in table:
            targets = tuple(
                _validate_glob(g, ctx)
                for g in _parse_str_list(table.get("targets"), "targets", ctx))
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
            regex_encoding = const_rewrite_encoding if kind == "rewrite" else "utf-8"
            for pattern in regex:
                try:
                    compiled_regex.append(re.compile(pattern.encode(regex_encoding)))
                except UnicodeEncodeError as e:
                    raise ConfigError(
                        f"{ctx}: regex {pattern!r} must be encodable as {regex_encoding}") from e
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
    if ci and bytes_hex:
        raise ConfigError(f"{ctx}: 'case_insensitive' is meaningless on a 'hex' rule")
    game_types = (_parse_str_list(table.get("game_types"), "game_types", ctx)
                  if "game_types" in table else ())

    replace = ""
    if "replace" in table:
        if kind != "rewrite":
            raise ConfigError(f"{ctx}: 'replace' is only valid on a kind='rewrite' rule")
        if not regex:
            raise ConfigError(f"{ctx}: 'replace' requires 'regex'")
        rep = table.get("replace")
        if not isinstance(rep, str) or not rep:
            raise ConfigError(f"{ctx}: 'replace' must be a non-empty string")
        for compiled in compiled_regex:
            _validate_template(rep, compiled, ctx)
        replace = rep

    return Rule(
        kind=kind, subject=subject, confidence=confidence,
        globs=globs, strings=strings, regex=regex, bytes_hex=bytes_hex, manifest=manifest,
        domains=domains, domain_search=domain_search,
        manifest_field=manifest_field, targets=targets, match=match,
        state=state, attributes=_parse_attributes(table, ctx),
        case_insensitive=ci, game_types=game_types, replace=replace,
    )


def _parse_bundle(data: dict[str, Any], *, default_source: str) -> RuleBundle:
    bundle_tbl = data.get("bundle")
    if not isinstance(bundle_tbl, dict):
        raise ConfigError("rule bundle: missing [bundle] table")
    bundle_tbl = cast("dict[str, Any]", bundle_tbl)
    name = _require_str(bundle_tbl, "name", "[bundle]")
    version = _require_str(bundle_tbl, "version", "[bundle]")
    source_raw = bundle_tbl.get("source")
    source = source_raw if isinstance(source_raw, str) else default_source
    updated = _require_str(bundle_tbl, "updated", "[bundle]")
    license_raw = bundle_tbl.get("license")
    license_str = license_raw if isinstance(license_raw, str) else ""

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
                      rules=rules, default_targets=default_targets, license=license_str)


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


def _user_rules_path(name: str) -> Path:
    """User override bundle: $XDG_CONFIG_HOME/dumpa/rules/<name>.toml (fallback ~/.config)."""
    import os
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "dumpa" / "rules" / f"{name}.toml"


def load_builtin(name: str) -> RuleBundle:
    """Load a bundle by name, preferring a user override over the vendored copy.

    A refreshed snapshot written by ``dumpa update-signatures`` lands at
    ``$XDG_CONFIG_HOME/dumpa/rules/<name>.toml`` and takes precedence over the in-repo
    vendored bundle (the floor) — the same user-override precedent as the domains seed.
    A malformed user copy raises (a refresh is explicit; silently falling back would hide
    a broken update).
    """
    user_path = _user_rules_path(name)
    if user_path.is_file():
        return load_bundle(user_path)
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


_QUANTIFIERS = frozenset("?*{")


def _split_alternation(pattern: str) -> list[str]:
    """Split a regex on its top-level ``|`` (respecting escapes and group nesting)."""
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            cur.append(c)
            cur.append(pattern[i + 1])
            i += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        if c == "|" and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def _mandatory_anchor(branch: str) -> bytes | None:
    """The longest literal run that *must* appear in any match of a single (no top-level
    ``|``) branch, or None if there is none of at least ``const_min_anchor_len`` chars.

    Only identifier runs at parenthesis-depth 0 and outside a ``[...]`` class are mandatory —
    anything inside a group could be an alternative (``(a|b)``) or optional (``(x)?``), and a
    char class is itself a one-of choice. A run whose following char is a ``*``/``?``/``{``
    quantifier has its last char trimmed (it may repeat zero times). Escaped chars break the
    run (conservative — a shorter anchor is still sound). Soundness matters: a missed anchor
    would make the prefilter skip a real match.
    """
    best = ""
    cur: list[str] = []

    def flush(nxt: str) -> None:
        nonlocal best, cur
        run = "".join(cur)
        cur = []
        if run and nxt in _QUANTIFIERS:
            run = run[:-1]
        if len(run) > len(best):
            best = run

    depth = 0
    in_class = False
    i = 0
    while i < len(branch):
        c = branch[i]
        if c == "\\" and i + 1 < len(branch):
            flush("")
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            flush("")
            in_class = True
        elif c == "(":
            flush("")
            depth += 1
        elif c == ")":
            flush("")
            depth = max(0, depth - 1)
        elif depth == 0 and (c.isalnum() or c == "_"):
            cur.append(c)
        else:
            flush(c if depth == 0 else "")
        i += 1
    flush("")
    return best.encode() if len(best) >= const_min_anchor_len else None


def _branch_anchors(source: str) -> list[bytes] | None:
    """One mandatory anchor per top-level alternative, or None if any branch has none.

    A class-path signature like ``com.foo.bar|com.baz`` yields an anchor per branch; the
    source is a candidate when *any* branch anchor is present. If even one branch has no
    mandatory literal run (e.g. ``(Integrity|Checksum).*(Check|Verify)`` — every literal sits
    inside an alternation group), the source can't be safely prefiltered, so it returns None
    and the caller always-runs it.
    """
    anchors: list[bytes] = []
    for branch in _split_alternation(source):
        anchor = _mandatory_anchor(branch)
        if anchor is None:
            return None
        anchors.append(anchor)
    return anchors


class _RegexSet:
    """Scan a window for many regex sources without one engine pass per source.

    A naive bundle of N regexes costs N full ``search``es per chunk; combining them into one
    alternation is far *worse* (CPython's ``re`` backtracks through every branch at every
    position — pathological once branches contain ``.``/quantifiers). The fast primitive is an
    alternation of **escaped literals**, which CPython accelerates with a prefix table: one
    near-free pass tells us *which* sources might be present. So each source contributes a
    literal anchor per top-level branch; one combined literal alternation per window yields the
    candidate set, and only those candidates' real regexes actually run. Sources with no usable
    anchor (no mandatory literal run) fall back to an always-run search.

    Reports first-hit ``(source, match)``; ``discard`` marks a source found so it is skipped and
    drops out of ``pending`` (which drives the streaming early-exit).

    ``precompiled`` carries already-lowered byte patterns (hex rules): raw bytes can't
    round-trip through ``src.encode()``, so the caller supplies the compiled pattern and
    its raw-byte anchors (case-sensitive). They share ``scan()`` with regex sources —
    everything is keyed by the ``src`` identity string (a regex source or a hex string).
    """

    def __init__(self, flagged: list[tuple[str, bool]],
                 precompiled: list[tuple[str, re.Pattern[bytes], list[bytes] | None]] = ()) -> None:
        self._all: set[str] = set()
        self._found: set[str] = set()
        self._real: dict[str, re.Pattern[bytes]] = {}            # anchor-gated
        self._standalone: dict[str, re.Pattern[bytes]] = {}      # always-run
        anchor_src: dict[bool, dict[bytes, set[str]]] = {True: {}, False: {}}
        for src, ci in flagged:
            self._register(src, re.compile(src.encode(), re.IGNORECASE if ci else 0),
                           _branch_anchors(src), ci, anchor_src)
        for src, compiled, anchors in precompiled:
            self._register(src, compiled, anchors, False, anchor_src)
        self._prefilters: list[tuple[re.Pattern[bytes], bool, dict[bytes, set[str]]]] = []
        for ci, table in anchor_src.items():
            if not table:
                continue
            # longest anchors first so the alternation prefers the most specific literal
            ordered = sorted(table, key=len, reverse=True)
            pattern = b"|".join(re.escape(a) for a in ordered)
            self._prefilters.append((re.compile(pattern, re.IGNORECASE if ci else 0), ci, table))

    def _register(self, src: str, compiled: re.Pattern[bytes], anchors: list[bytes] | None,
                  ci: bool, anchor_src: dict[bool, dict[bytes, set[str]]]) -> None:
        """Index one source: anchor-gated when it has mandatory literals, else always-run."""
        if src in self._all:
            return
        self._all.add(src)
        if anchors is None:
            self._standalone[src] = compiled
            return
        self._real[src] = compiled
        for anchor in anchors:
            key = anchor.lower() if ci else anchor
            anchor_src[ci].setdefault(key, set()).add(src)

    @property
    def pending(self) -> set[str]:
        return self._all - self._found

    def discard(self, key: str) -> None:
        self._found.add(key)

    def scan(self, window: bytes, *, at_eof: bool = False) -> list[tuple[str, re.Match[bytes]]]:
        """First match per not-yet-found source in `window`.

        A match ending exactly at the window edge is deferred (it may be truncated and
        will reappear via the next chunk's overlap) unless `at_eof` — the final tail of a
        file has no successor, so an edge match there is recorded.
        """
        n = len(window)
        candidates: set[str] = set()
        for rx, ci, table in self._prefilters:
            for anchor_match in rx.finditer(window):
                key = anchor_match.group().lower() if ci else anchor_match.group()
                candidates |= table.get(key, set())
        hits: list[tuple[str, re.Match[bytes]]] = []
        seen: set[str] = set()
        for src in candidates:
            if src in self._found or src in seen:
                continue
            real_match = self._real[src].search(window)
            if real_match is not None and (at_eof or real_match.end() != n):
                seen.add(src)
                hits.append((src, real_match))
        for src, rx in self._standalone.items():
            if src in self._found or src in seen:
                continue
            standalone_match = rx.search(window)
            if standalone_match is not None and (at_eof or standalone_match.end() != n):
                seen.add(src)
                hits.append((src, standalone_match))
        return hits


def _record_regex_hit(found: dict[str, _Hit], key: str,
                      match: re.Match[bytes], rel: str, window_start: int) -> None:
    text = match.group()[:const_max_match_text].decode("latin-1")
    found[key] = (rel, window_start + match.start(), text)


def _scan_content(files: list[Path], literals: dict[str, bytes],
                  rset: _RegexSet | None, extracted_dir: Path) -> dict[str, _Hit]:
    """First-hit (relpath, offset, text) for each literal/regex key; streams with overlap."""
    found: dict[str, _Hit] = {}
    pending_literals = set(literals)
    has_regex = rset is not None and bool(rset.pending)
    overlap = max((len(v) for v in literals.values()), default=1)
    overlap = max(overlap - 1, const_regex_overlap if has_regex else 0)

    def regex_pending() -> bool:
        return rset is not None and bool(rset.pending)

    for path in files:
        if not pending_literals and not regex_pending():
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
                    if rset is not None:
                        for key, m in rset.scan(window):
                            _record_regex_hit(found, key, m, rel, window_start)
                            rset.discard(key)
                    if not pending_literals and not regex_pending():
                        break
                    base += len(chunk)
                    tail = window[-overlap:] if overlap > 0 else b""
                if tail and regex_pending():
                    window_start = base - len(tail)
                    assert rset is not None
                    for key, m in rset.scan(tail, at_eof=True):
                        _record_regex_hit(found, key, m, rel, window_start)
                        rset.discard(key)
        except OSError:
            logger.debug("content scan: cannot read %s", path, exc_info=True)
            continue
    return found


def _content_finding(rule: Rule, bundle: RuleBundle, hits: dict[str, _Hit]) -> Finding:
    evidence: list[Evidence] = []
    locations: list[Location] = []
    is_regex = bool(rule.regex)
    is_bytes = bool(rule.bytes_hex)
    for key in rule.keys:
        if key not in hits:
            continue
        rel, offset, text = hits[key]
        if is_bytes:
            shown = text.encode("latin-1").hex(" ")
            description = f"byte pattern [{key}] matched {shown} in {rel}"
        elif is_regex:
            shown = text
            description = f"pattern /{key}/ matched {text!r} in {rel}"
        else:
            shown = text
            description = f"string '{key}' found in {rel}"
        evidence.append(Evidence(
            description=description, snippet=shown, tool="rules", rule_version=bundle.version,
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
        # Literal keys come from `strings` and, for domain-search rules, their `domains`
        # (never from regex/hex rules — those go through the _RegexSet).
        literals = {k: k.encode() for rule in group for k in rule.keys
                    if not rule.regex and not rule.bytes_hex}
        # Regex sources carry a per-rule case flag (IGNORECASE for ported dumpcs rules);
        # _RegexSet combines them into few alternation passes and keys hits by source so
        # _content_finding can look them up via rule.keys.
        flagged = [(p, rule.case_insensitive) for rule in group for p in rule.regex]
        # Hex rules lower to precompiled byte patterns (keyed by the hex string).
        byte_specs = [(h, *compile_hex(h)) for rule in group for h in rule.bytes_hex]
        rset = _RegexSet(flagged, byte_specs) if (flagged or byte_specs) else None
        hits = _scan_content(_content_targets(root, targets), literals, rset, root)
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


_ENGINE_CONFIDENCE_RANK = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}


def _globs_match_names(rule: Rule, names: list[PurePosixPath]) -> bool:
    """True when the rule's globs fire against a flat list of archive entry names.

    Mirrors `_rule_matches` semantics (`match=any` -> any glob hits; `match=all` -> all
    do) but tests `PurePosixPath.full_match` over names instead of walking a tree.
    """
    matched = 0
    for glob in rule.globs:
        if any(name.full_match(glob) for name in names):
            matched += 1
            if rule.match != const_match_all:
                return True
    return rule.match == const_match_all and matched == len(rule.globs)


def probe_engine_from_names(names: Iterable[str]) -> str | None:
    """Highest-confidence engine whose path globs match any archive entry name.

    A glob-only subset of the `engines` bundle for callers (`dumpa info`) that hold a zip
    namelist but have no extracted tree, so the full `apply_bundle` path/manifest matchers
    cannot run. Manifest-component rules are ignored; the native-library and asset globs
    still identify the deep-helper engines. For an .xapk only the base apk's names are
    visible here, so an engine whose native lib is split into an arch apk with no base-apk
    asset residue may be missed — acceptable for fast triage; full detection lives in
    `analyze` via `scanners.engine`.
    """
    name_list = [PurePosixPath(n) for n in names]
    bundle = load_builtin("engines")
    best_rank = 0
    best_subject: str | None = None
    for rule in bundle.rules:
        if not rule.globs or not _globs_match_names(rule, name_list):
            continue
        rank = _ENGINE_CONFIDENCE_RANK[rule.confidence]
        if rank > best_rank:           # first rule at the top rank wins (bundle order)
            best_rank = rank
            best_subject = rule.subject
    return best_subject
