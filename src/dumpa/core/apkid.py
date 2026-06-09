"""Import the APKiD signature set into a dumpa ``protections`` rule bundle.

APKiD (https://github.com/rednaga/APKiD) ships hundreds of YARA rules that fingerprint
Android *packers*, *protectors*, *obfuscators*, and *anti-vm / anti-debug* tooling — the
exact protection inventory dumpa reports, but far broader than the ~18 hand-curated rules
in ``protections.toml``. This module is a *pure transform*: a blob of concatenated YARA
rule text -> a TOML ``protection`` rule bundle string, no network and no disk I/O, so it is
trivially testable. The networked multi-file fetch lives in ``commands.update_signatures``.

dumpa has no YARA engine and wants no new dependency, so this does **not** run YARA — it
lowers the *usable subset* of each rule onto dumpa's own matchers (``strings`` / ``hex`` /
``regex``) and conservatively **drops** anything it cannot represent faithfully (logged),
exactly like ``core.exodus`` drops an uncompilable signature. One un-portable upstream rule
can never break the bundle.

What is kept vs dropped:

- **strings** — text ``$x = "..."`` -> a ``strings`` (literal) rule; hex ``$x = { AA ?? BB }``
  (only fixed bytes + ``??`` full-byte wildcards) -> a ``hex`` rule; regex ``$x = /.../`` -> a
  ``regex`` rule. Hex with jumps ``[n]`` / alternation ``(..|..)`` / nibble wildcards ``?A``,
  and ``wide`` (UTF-16) strings, are dropped (un-portable to a UTF-8 byte scan).
- **condition** — only ``... any of them`` and ``... all of them`` (any leading format guard
  such as ``dex.* and`` is ignored — it merely scoped the scan, which dumpa already does by
  streaming dex+native), plus a bare single ``$id``. Conditions using string offsets (``@``),
  counts (``#``), ``for`` loops, ``filesize``/``uintN`` math, etc. are dropped.
- **category** — derived from the rule's *source file* path (``packers/`` -> ``packer``,
  ``protectors/`` -> ``anti-tamper``, ``obfuscators/`` -> ``obfuscator``, ``anti_vm`` /
  ``anti_debug`` -> ``anti-analysis`` / ``anti-debug``). Rules from unmapped paths (e.g.
  ``compilers/`` — dx/r8 are not protections) are dropped. The fetch layer prefixes each
  file's text with a ``// dumpa-apkid-source: <path>`` marker so this transform can read it.
- **subject** — ``meta.description`` if present, else the humanized rule name.
- all emitted rules are ``confidence = "medium"``; the curated ``protections.toml`` stays
  authoritative (it wins on a subject collision at scan time).

Scope note: rules are emitted without ``targets`` (scanned over the whole extracted tree).
APKiD scopes by file format in its condition; reproducing that as per-rule ``lib/**/*.so``
targets is a future refinement.

Reuses Exodus' ``_toml_basic`` (TOML escaping) and ``_valid_signature`` (compile + min-len
guard) — general-purpose, not Exodus-specific.
"""

from __future__ import annotations

import hashlib
import logging
import re

from dumpa.core.errors import ConfigError
from dumpa.core.exodus import _toml_basic, _valid_signature
from dumpa.core.rules import compile_hex

logger = logging.getLogger("dumpa")

const_apkid_tree_url = (
    "https://api.github.com/repos/rednaga/APKiD/git/trees/master?recursive=1"
)
const_apkid_raw_base = "https://raw.githubusercontent.com/rednaga/APKiD/master/"
const_apkid_rules_prefix = "apkid/rules/"
const_bundle_name = "protections-apkid"
const_source = f"APKiD ({const_apkid_tree_url})"
const_license = (
    "APKiD signature data — see https://github.com/rednaga/APKiD "
    "(rednaga/APKiD, dual-licensed GPL-3.0 / commercial; this bundle derives from the "
    "GPL-3.0 rules)"
)
const_confidence = "medium"
const_source_marker = "// dumpa-apkid-source:"
const_min_string_len = 4        # drop trivially-broad text literals

# Source-path keyword -> dumpa protection category. A rule whose source path matches none of
# these is dropped (e.g. compilers/, which fingerprints dx/r8 — not a protection).
const_category_keywords: tuple[tuple[str, str], ...] = (
    ("packer", "packer"),
    ("protector", "anti-tamper"),
    ("obfuscator", "obfuscator"),
    ("manipulator", "anti-tamper"),
    ("anti_vm", "anti-analysis"),
    ("antivm", "anti-analysis"),
    ("emulator", "anti-analysis"),
    ("anti_debug", "anti-debug"),
    ("antidebug", "anti-debug"),
    ("anti_disassem", "anti-analysis"),
)

# Condition constructs dumpa cannot represent -> drop the whole rule (precision over recall).
_UNSUPPORTED_CONDITION = re.compile(r"@|#|!|\bfor\b|\bfilesize\b|\buint\d|\bint\d|~|\bat\b|\.\.")


def _category_for(source_path: str) -> str | None:
    low = source_path.lower()
    for needle, category in const_category_keywords:
        if needle in low:
            return category
    return None


def _strip_comments(text: str) -> str:
    """Remove ``//`` line and ``/* */`` block comments, preserving ``"..."`` and ``/.../``.

    Keeps the source markers (``// dumpa-apkid-source: ...``) — they are re-extracted before
    this runs, so by the time we strip we no longer need them; callers pass per-file text.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:min(j + 1, n)])
            i = j + 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _match_rule_body(text: str, open_brace: int) -> int:
    """Return the index just past the ``}`` closing the rule body opened at ``open_brace``.

    Counts braces while skipping ``"..."`` strings and ``/.../`` regexes (whose contents may
    contain braces). Comments are already stripped. Returns -1 on an unbalanced body.
    """
    depth = 0
    i, n = open_brace, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
            continue
        if c == "/":
            i += 1
            while i < n and text[i] != "/":
                i += 2 if text[i] == "\\" else 1
            i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


_RULE_HEADER = re.compile(r"\brule\s+([A-Za-z_]\w*)\s*(?::[^\{]*)?\{")
_SECTION = re.compile(r"\b(meta|strings|condition)\s*:")
_META_LINE = re.compile(r'(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"')
_STRING_DEF = re.compile(r"\$(\w+)\s*=\s*")


def _humanize(name: str) -> str:
    return name.replace("_", " ").strip() or name


def _decode_yara_text(raw: str) -> str:
    """Decode a YARA double-quoted string body's escapes to the literal bytes' text form."""
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c == "\\" and i + 1 < n:
            nxt = raw[i + 1]
            if nxt == "x" and i + 3 < n:
                try:
                    out.append(chr(int(raw[i + 2:i + 4], 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            out.append({"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, nxt))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


class _Str:
    __slots__ = ("kind", "nocase", "usable", "value")

    def __init__(self, kind: str, value: str, nocase: bool, usable: bool) -> None:
        self.kind = kind            # "strings" | "hex" | "regex"
        self.value = value
        self.nocase = nocase
        self.usable = usable


def _parse_string_def(body: str) -> _Str | None:
    """Parse one string definition body (the part after ``$id =``) into a ``_Str``.

    Returns None when the value is not a recognizable text / hex / regex literal.
    """
    body = body.strip()
    if not body:
        return None
    if body[0] == '"':
        end = 1
        while end < len(body) and body[end] != '"':
            end += 2 if body[end] == "\\" else 1
        value = _decode_yara_text(body[1:end])
        mods = body[end + 1:].lower()
        nocase = "nocase" in mods
        wide_only = "wide" in mods and "ascii" not in mods
        usable = (not wide_only) and len(value) >= const_min_string_len
        return _Str("strings", value, nocase, usable)
    if body[0] == "{":
        end = body.find("}")
        if end < 0:
            return None
        inner = body[1:end]
        # Only fixed bytes and full-byte `??` wildcards are portable to compile_hex; jumps
        # `[n]`, alternation `(..|..)`, and nibble wildcards (`?A`) are not.
        compact = "".join(inner.split())
        portable = (
            all(ch in "0123456789abcdefABCDEF?" for ch in compact)
            and len(compact) % 2 == 0
            and all(compact[i:i + 2] == "??" or "?" not in compact[i:i + 2]
                    for i in range(0, len(compact), 2))
        )
        if not portable:
            return _Str("hex", compact, False, False)
        try:
            compile_hex(compact)
        except ConfigError:
            return _Str("hex", compact, False, False)
        return _Str("hex", compact, False, True)
    if body[0] == "/":
        end = 1
        while end < len(body) and body[end] != "/":
            end += 2 if body[end] == "\\" else 1
        pattern = body[1:end]
        mods = body[end + 1:].lower()
        nocase = "i" in mods or "nocase" in mods
        wide_only = "wide" in mods and "ascii" not in mods
        usable = (not wide_only) and _valid_signature(pattern) is not None
        return _Str("regex", pattern, nocase, usable)
    return None


def _split_string_defs(strings_block: str) -> dict[str, _Str]:
    """Parse a ``strings:`` section body into ``{id: _Str}`` (order-preserving dict)."""
    defs: dict[str, _Str] = {}
    matches = list(_STRING_DEF.finditer(strings_block))
    for idx, m in enumerate(matches):
        start = m.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(strings_block)
        parsed = _parse_string_def(strings_block[start:end])
        if parsed is not None:
            defs[m.group(1)] = parsed
    return defs


def _condition_mode(condition: str) -> str | None:
    """Classify a YARA condition into ``"any"`` / ``"all"`` (over all strings), else None.

    Any leading format guard (``dex.* and`` / ``elf.* and``) is ignored — it only scoped the
    scan. Conditions using offsets / counts / loops / file math are unsupported -> None.
    """
    norm = re.sub(r"\s+", " ", condition).strip().lower()
    if not norm or _UNSUPPORTED_CONDITION.search(norm):
        return None
    if norm == "any of them" or norm.endswith(" any of them"):
        return "any"
    if norm == "all of them" or norm.endswith(" all of them"):
        return "all"
    if re.fullmatch(r"\$\w+", norm):        # a single string reference
        return "any"
    return None


def _emit_rules(subject: str, category: str, defs: dict[str, _Str], mode: str) -> list[str]:
    """Lower a classified rule into TOML ``[[rule]]`` blocks (one per matcher kind)."""
    usable = [s for s in defs.values() if s.usable]
    if not usable:
        return []
    by_kind: dict[str, list[_Str]] = {}
    for s in usable:
        by_kind.setdefault(s.kind, []).append(s)

    if mode == "all":
        # An AND must cover every defined string in one rule: if any string was dropped, or
        # the strings span more than one matcher kind, the AND cannot be faithfully kept.
        if len(usable) != len(defs) or len(by_kind) != 1:
            return []
        kind, group = next(iter(by_kind.items()))
        return [_rule_block(subject, category, kind, group, match="all")]

    # mode == "any": one rule per kind (independent presence preserves the OR).
    return [_rule_block(subject, category, kind, group, match="any")
            for kind, group in by_kind.items()]


def _rule_block(subject: str, category: str, kind: str, group: list[_Str], *, match: str) -> str:
    lines = [
        "[[rule]]",
        'kind = "protection"',
        f"subject = {_toml_basic(subject)}",
        f"category = {_toml_basic(category)}",
        f'confidence = "{const_confidence}"',
    ]
    if match == "all" and len(group) > 1:
        lines.append('match = "all"')
    if kind != "hex" and any(s.nocase for s in group):
        lines.append("case_insensitive = true")
    values = ", ".join(_toml_basic(s.value) for s in group)
    lines.append(f"{kind} = [{values}]")
    return "\n".join(lines)


def apkid_rules_to_bundle_toml(yara_text: str, *, fetched: str) -> str:
    """Transform concatenated APKiD YARA text into a dumpa protection-bundle TOML string.

    ``yara_text`` is the concatenation of APKiD's ``*.yara`` files, each prefixed by a
    ``// dumpa-apkid-source: <path>`` marker (see ``commands.update_signatures``). ``fetched``
    is the import date (YYYY-MM-DD). The bundle ``version`` is ``apkid.<subjects>.<hash8>``
    over the emitted body, so re-importing identical upstream data yields an identical
    version (does not spuriously bust the per-scanner content cache).
    """
    blocks: list[str] = []
    subjects: set[str] = set()
    kept = dropped = 0

    source_path = ""
    # Walk the text rule-by-rule, tracking the most recent source marker for category.
    pos = 0
    while True:
        marker = yara_text.find(const_source_marker, pos)
        header = _RULE_HEADER.search(yara_text, pos)
        if header is None:
            break
        if marker != -1 and marker < header.start():
            line_end = yara_text.find("\n", marker)
            source_path = yara_text[marker + len(const_source_marker):
                                    (line_end if line_end != -1 else len(yara_text))].strip()
            pos = marker + len(const_source_marker)
            continue

        name = header.group(1)
        body_end = _match_rule_body(yara_text, header.end() - 1)
        pos = header.end() if body_end < 0 else body_end
        if body_end < 0:
            continue

        category = _category_for(source_path)
        if category is None:
            continue

        body = _strip_comments(yara_text[header.end():body_end - 1])
        sections = list(_SECTION.finditer(body))
        named: dict[str, str] = {}
        for idx, sm in enumerate(sections):
            seg_end = sections[idx + 1].start() if idx + 1 < len(sections) else len(body)
            named[sm.group(1)] = body[sm.end():seg_end]
        if "condition" not in named:
            continue

        mode = _condition_mode(named["condition"])
        if mode is None:
            dropped += 1
            continue
        defs = _split_string_defs(named.get("strings", ""))
        if not defs:
            dropped += 1
            continue

        meta = dict(_META_LINE.findall(named.get("meta", "")))
        subject = _decode_yara_text(meta.get("description", "")).strip() or _humanize(name)
        rule_blocks = _emit_rules(subject, category, defs, mode)
        if not rule_blocks:
            dropped += 1
            continue
        kept += 1
        subjects.add(subject)
        blocks.extend(rule_blocks)

    logger.debug("apkid import: kept %d rule(s), dropped %d un-portable", kept, dropped)

    body_text = "\n\n".join(blocks)
    digest = hashlib.sha256(body_text.encode()).hexdigest()[:8]
    version = f"apkid.{len(subjects)}.{digest}"
    head = "\n".join([
        "# Imported APKiD protection signatures (generated — do not edit by hand).",
        "# Regenerate with `dumpa update-signatures --db apkid`. Curated `protections.toml`",
        "# stays authoritative; on a subject collision the curated rule wins.",
        "",
        "[bundle]",
        f'name = "{const_bundle_name}"',
        f'version = "{version}"',
        f"source = {_toml_basic(const_source)}",
        f'updated = "{fetched}"',
        f"license = {_toml_basic(const_license)}",
        "",
    ])
    return head + ("\n" + body_text + "\n" if body_text else "")
