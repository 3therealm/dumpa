# Design — `dumpa rewrite` (Phase 8 smali find-and-replace)

Status: design. Implements the requirements spec discovered in `/sc:brainstorm`.
Next step: `/sc:implement`.

## 1. Scope and decisions

Bundle-driven find-and-replace over the decoded **smali** tree. First code-*modification*
surface in the toolkit. Locked decisions (from brainstorm):

- **Decode source:** reuse the existing `apktool d` output (`Workspace.smali_dir`). No
  baksmali path. baksmali stays doctor-only.
- **Selection UX:** flag-driven only (`--select all | 2,5 | 1-3,7`). No interactive prompt.
- **Audit trail:** every applied edit becomes a `Finding`/`Evidence` in the unified report
  model, so it flows to JSON/MD/HTML/CSV exporters with zero new exporter code.
- Original input file is never touched; edits land on the workspace smali copy and are
  reversible by re-decode.
- Re-sign is opt-in (`--rebuild --signing <preset>`), gated behind explicit invocation,
  reusing the Phase 1 signing path. Never automatic.

## 2. Component map

```
cli.py
  rewrite()  @app.command  -> run_command(lambda: rewrite_cmd.rewrite(...))

commands/rewrite.py              NEW  — orchestration only
  rewrite(workspace, pattern, replace, select, category, rebuild, signing, out)
     load workspace + guard smali
     load_bundle(pattern) [+ load_bundle(replace)]
     core.rewrite.plan_edits(...)      -> RewritePlan (preview)
     render preview (always)
     if applying: core.rewrite.apply_edits(...) -> [AppliedEdit]
                  reporting hook: edits -> Findings -> write report
     if rebuild:  pack_align_sign(...)  (reuse convert.build)

core/rewrite.py                  NEW  — pure engine, no Typer/no I/O side effects beyond smali write
  RewriteRule (view over Rule: regex + replace + category)
  Match        (index, rule, file_rel, byte_offset, line, col, before, after, context)
  RewritePlan  (matches: list[Match], skipped/warnings)
  AppliedEdit  (the subset actually written, with before/after)
  plan_edits(smali_dir, rules, *, categories) -> RewritePlan
  apply_edits(smali_dir, plan, selection) -> list[AppliedEdit]
  parse_selection("1-3,7"|"all", n) -> set[int]

core/rules.py                    EXTEND
  Rule.replace: str = ""                      (new optional field)
  _parse_rule: accept kind="rewrite"; require regex; parse `replace` template;
               validate backref template against the rule's regex group count.

dumpa/rules/                     (user-supplied bundles live outside the package;
                                  built-ins optional — none shipped initially)
```

The split mirrors the codebase convention: `core/*` is pure + testable, `commands/*` is
thin orchestration, `cli.py` is Typer glue. Same shape as `repack` (`commands/repack.py`
delegating to `convert.build.pack_align_sign`).

## 3. Rule-model extension

`rewrite` is a **regex rule with a replacement template**. It reuses the existing
`regex` field (already compiled as `bytes`, already validated) and the `targets` glob
(default `**/*.smali`). One new field:

```python
@dataclass(frozen=True)
class Rule:
    ...
    replace: str = ""        # substitution template; only meaningful for kind="rewrite"
```

`_parse_rule` changes:

- When `kind == "rewrite"`: the rule must carry `regex` (the existing "exactly one of
  globs/strings/regex/manifest/domains" check already forces this — `rewrite` rides the
  `regex` branch). `category`/`confidence`/`subject` parse as today.
- `replace` is parsed only when present. A `--pattern` (match-only) bundle omits `replace`;
  a `--replace` bundle includes it. **Validation:** if `replace` is set, re-run the rule's
  compiled regex group count and reject `\g<N>` / `\N` backrefs that exceed it (fail closed
  at load, not mid-apply). Use `re.Match.expand`-compatible templates; recommend `\g<1>`
  form in docs (smali registers `v1`/`p0` sit adjacent to digits — `\1` is ambiguous).
- A bundle may mix `kind="rewrite"` rules with detection rules in theory, but `rewrite`
  the command consumes only `kind=="rewrite"` rules and ignores the rest (warn on skip).

Why ride `regex` rather than add a 6th matcher kind: the streaming primitive, anchor
prefilter, and validation already exist for `regex`. `rewrite` needs *line/offset
enumeration with replacement*, which is a different traversal than detection's
first-hit-per-key — so the **engine** is new, but the **rule shape** is a thin superset.

## 4. Engine design (`core/rewrite.py`)

### 4.1 Why not reuse `_scan_content`

The detection scanner records **first hit per key** and early-exits. `rewrite` needs
**every** match, in deterministic order, each individually selectable. Different
traversal. But smali files are small (per-class `.smali`, typically < 100 KB; the giant
artifacts are `dump.cs`/`script.json`, which are *not* rewrite targets). So the engine
reads each target file **whole** — simpler, and the memory argument that drives streaming
elsewhere does not apply to the smali tree.

(If a pathological multi-MB smali file appears, cap with `const_max_content_scan_bytes`
and warn — same guard as content scan.)

### 4.2 Match enumeration → stable index

```
plan_edits(smali_dir, rules, *, categories) -> RewritePlan
  files = sorted(smali_dir rglob over union of rule targets)   # deterministic
  for each file (sorted), for each rule (bundle order):
      for m in rule.compiled.finditer(file_bytes):
          record Match(byte_offset, line, col, before=m.group(),
                       after=m.expand(template) if rule.replace else None,
                       context=<line text>)
  assign global index by (file_sort, byte_offset, rule_order)  # stable, reproducible
```

**Index stability** (open Q3 from spec): the index anchors *internally* on
`(file_relpath, byte_offset, rule_index)` — byte offset gives a total order and is what
`apply_edits` needs to substitute correctly, so it stays the source of truth. Re-running
`plan_edits` on the same smali tree yields identical indices (no `Date`/random; pure
function of bytes + rule order).

**Human locator** (resolved Q3): the *displayed* locator is `file:line` when that line
holds a single match, and `file:line@col` when the line holds more than one (col = 1-based
char offset within the line). `plan_edits` computes per-line match counts in a second pass
so the preview can pick the short form by default and disambiguate only where needed. The
selectable index is unchanged either way — display sugar, not a second addressing scheme.

**Category filter** (open Q4): `categories` constrains both preview and apply — a rule
whose `category` is not in the selected set is dropped before enumeration, so preview
indices already reflect the filter. Consistent, no index drift between preview and apply.

### 4.3 Apply

```
apply_edits(smali_dir, plan, selection: set[int]) -> list[AppliedEdit]
  group selected matches by file
  for each file: apply substitutions right-to-left by offset      # offsets stay valid
      verify each selected match still matches at its offset       # guard against drift
      write file back (same encoding: latin-1 / raw bytes)
  return AppliedEdit per write
```

Right-to-left application means earlier offsets are unaffected by length changes. Files
are written in place under `smali/` (the workspace copy). The original input apk is never
opened.

### 4.4 Overlap / conflict rule

If two **selected** matches overlap in one file → hard error (ambiguous edit), name both
indices, write nothing for that file. Unselected overlaps are fine (only one chosen).

## 5. Command flow (`commands/rewrite.py`)

```
rewrite(workspace, *, pattern, replace=None, select=None,
        category=(), rebuild=False, signing=None, out=None):
    ws = Workspace(root=workspace.resolve())
    guard: ws.read_meta() is not None        else DumpaError "run dumpa unpack first"
    guard: ws.has_smali()                     else  (open Q1) -> auto-decode OR error
    rules = rewrite rules from load_bundle(pattern) (+ merge replace templates from
            load_bundle(replace) by subject/regex identity, if --replace given)
    plan = core.rewrite.plan_edits(ws.smali_dir, rules, categories=category)
    render_preview(plan)                       # always: index, file:line, category, before[, after]
    if select is None or replace is None:
        return                                 # preview-only (dry-run default)
    selection = parse_selection(select, len(plan.matches))
    edits = core.rewrite.apply_edits(ws.smali_dir, plan, selection)
    findings = [edit_to_finding(e) for e in edits]
    write/merge into ws report                 # audit trail
    if rebuild:
        config/registry/sign as repack does
        pack_align_sign(registry, ws.smali_dir, out_path, sign_config)
```

`--pattern` alone, or `--replace` without `--select`, is preview-only. Applying requires
**both** a `--replace` bundle and an explicit `--select`. `--rebuild` is independent and
only meaningful after an apply.

### 5.1 `parse_selection`

- `"all"` → every index `0..n-1`.
- comma list of ints and `lo-hi` ranges → expanded set; bounds-checked (reject an index
  ≥ n or a backwards range) with a `ConfigError`.

## 6. Report integration (audit trail)

Each `AppliedEdit` → one `Finding`:

```python
Finding(
    kind="rewrite",
    subject=rule.subject,                 # e.g. "point analytics host at localhost"
    confidence=rule.confidence,
    state=FindingState.PRESENT,           # see note
    attributes={"category": rule.category, "action": "applied"},
    evidence=[Evidence(
        description=f"rewrote {rel}:{line} — {before!r} -> {after!r}",
        snippet=f"{before} -> {after}",
        tool="rewrite", rule_version=bundle.version)],
    locations=[Location(file_path=rel, file_offset=offset)],
)
```

`FindingState` has no "applied" value. Two options:

- **A (chosen):** carry the applied/preview distinction in `attributes["action"]`
  (`"applied"` vs `"preview"`). Zero model change; exporters already render attributes.
- B: add `FindingState.MODIFIED`. Cleaner semantically but touches the shared enum and
  every state-aware consumer (diff, density, renderers). Heavier than the feature warrants.

Findings merge into the workspace report so `dumpa export` surfaces the edit log in every
format. The `rewrite` kind is new but additive — no exporter needs a code change because
they iterate findings generically.

## 7. CLI surface (`cli.py`)

```python
@app.command()
def rewrite(
    workspace: Path = typer.Argument(..., help="dumpa workspace (run `dumpa unpack --decode` first)."),
    pattern: Path = typer.Option(..., "--pattern", help="TOML bundle of rewrite rules to match."),
    replace: Path | None = typer.Option(None, "--replace", help="TOML bundle with `replace` templates; required to apply."),
    select: str | None = typer.Option(None, "--select", help="all | index list/ranges over the preview, e.g. 2,5 or 1-3,7."),
    category: list[str] = typer.Option([], "--category", help="Limit to these rule categories (repeatable)."),
    rebuild: bool = typer.Option(False, "--rebuild", help="After applying, apktool b -> zipalign -> re-sign into a patched apk."),
    signing: str | None = typer.Option(None, "--signing", help="Signing preset for --rebuild (unsigned|debug|<keystore>)."),
    out: Path | None = typer.Option(None, "--out", help="Patched apk path for --rebuild."),
) -> None:
    run_command(lambda: rewrite_cmd.rewrite(
        workspace, pattern=pattern, replace=replace, select=select,
        category=category, rebuild=rebuild, signing=signing, out=out))
```

Exit codes ride the existing `run_command` map (ConfigError→8, ToolExecutionError→5, …).

## 8. Data shapes

```python
@dataclass(frozen=True)
class Match:
    index: int
    rule_subject: str
    category: str
    confidence: Confidence
    file_rel: str
    byte_offset: int
    line: int
    col: int
    before: str
    after: str | None          # None in match-only (--pattern without --replace)
    context: str               # the full source line, for preview
    line_match_count: int      # matches on this line; >1 -> locator shows line@col

    @property
    def locator(self) -> str:  # "file:line" single / "file:line@col" multi
        return (f"{self.file_rel}:{self.line}@{self.col}"
                if self.line_match_count > 1 else f"{self.file_rel}:{self.line}")

@dataclass(frozen=True)
class RewritePlan:
    matches: tuple[Match, ...]
    warnings: tuple[str, ...]  # skipped non-rewrite rules, oversized files

@dataclass(frozen=True)
class AppliedEdit:
    match: Match
    rule_version: str
```

## 9. Test plan (TDD targets)

`core/rewrite.py` is pure → unit-testable without an apk:

- `parse_selection`: `all`, `2,5`, `1-3,7`, out-of-range (raises), reversed range (raises).
- `plan_edits`: deterministic indices across two runs; multi-match-per-line distinct
  offsets; category filter drops rules + does not shift surviving indices vs unfiltered-then-filtered.
- `apply_edits`: right-to-left correctness when replacement changes length; overlap of two
  selected matches → error, no write; `\g<1>` backref expansion over a smali `const-string`.
- round-trip: original input file byte-identical after any run (apply touches only `smali/`).
- rule loader: `kind="rewrite"` accepted; `replace` with out-of-range backref rejected at load.
- command-level: `--pattern` alone writes nothing; `--replace` without `--select` writes
  nothing; apply produces `rewrite` findings; `--rebuild` calls `pack_align_sign` (mock).

Golden fixture: a tiny synthetic smali tree (3 files) + a rewrite bundle, asserting the
preview table and post-apply bytes.

## 10. Resolved questions

1. **Auto-decode when `smali/` missing** — RESOLVED: **auto-run `apktool d`** (matches
   `analyze` auto-dump ergonomics), behind the existing apktool requirement check. No
   error-and-instruct path.
2. **Backref escaping** — RESOLVED: standardize on `\g<N>`; doc-warn against `\N` near
   register digits. Loader validates group count at load (fail closed).
3. **Match locator** — RESOLVED: internal index stays byte-offset (total order + apply
   correctness); displayed locator is `file:line` for a single match on the line,
   `file:line@col` when the line has >1 match (see §4.2, `Match.locator`).
4. **Category in preview vs apply** — RESOLVED: constrains both, no index drift.
5. **Encoding** — RESOLVED: read/write smali as raw bytes (latin-1 round-trip) to stay
   byte-exact and avoid re-encoding surprises. Verify against an apktool smali sample with
   non-ASCII string literals during implementation.
