# Design: Closeout Sweep

Five small, unblocked roadmap gaps batched into one design. Ordered by effort.
This document is design only — interfaces, data shapes, call sites, and test plan.
No implementation.

| # | Item | Phase | Touches |
|---|------|-------|---------|
| 1 | `info` engine field | 1 | `commands/info.py`, `core/rules.py` |
| 2 | debug-cert detection | 1 | `tools/apksigner.py`, `core/report.py`, `commands/info.py`, `reporting` |
| 3 | tracker taxonomy gaps | 5 | `rules/trackers.toml` (data only) |
| 4 | diff changed native symbols | 10 | `core/diff.py`, `commands/diff.py`, `commands/analyze.py` |
| 5 | diff changed Unity methods | 10 | `core/dumpcs_methods.py` (new), `core/diff.py`, `commands/diff.py` |

Items 4 and 5 share one `diff`-command refactor (live workspaces), specified once in §4.

---

## 1. `info` engine field

### Constraint

`dumpa info` is the fast-triage command: no apktool decode, no extraction, no
persistent workspace (`commands/info.py` docstring). The engine scanner
(`scanners/engine.py`) runs `apply_bundle` over `ws.extracted_dir` — a full
extraction. Reusing it would break the `info` contract.

### Approach

Detect engine from the APK's **zip central-directory namelist** — the entry names
alone, no payload read. The `engines` bundle is glob-dominated (12 of 16 rules are
`globs`; see `rules/engines.toml`), and every glob is a path pattern matchable
against a flat name list. The 4 `manifest`-component rules are *supplements* and are
skipped here (`info` has no parsed AXML; it only has `aapt` badging). Native-lib and
asset globs (`lib/*/libil2cpp.so`, `assets/bin/Data/**`) cover the deep-helper engines
even when manifest rules are absent.

### New code — `core/rules.py`

Add a names-based engine probe that reuses the existing glob predicate:

```python
def probe_engine_from_names(names: Iterable[str]) -> str | None:
    """Highest-confidence engine whose path globs match any archive entry name.

    Glob-only subset of the engines bundle for callers (info) that have a zip
    namelist but no extracted tree. Manifest-component rules are ignored.
    """
```

- Load the builtin `engines` bundle (`load_builtin("engines")`).
- For each rule with `globs`, test each glob against the name list with the same
  matcher `apply_bundle` uses for `path_glob` (extract that predicate into a shared
  `_glob_matches(glob, names)` helper so detection logic stays single-sourced; do not
  fork fnmatch semantics).
- Return the subject of the highest-confidence matching rule, confidence ranked as in
  `scanners.primary_engine` (HIGH > MEDIUM > LOW; bundle order breaks ties). Reuse the
  existing `_CONFIDENCE_RANK`-equivalent ordering rather than redefining it.

### Call site — `commands/info.py`

`info()` already resolves the probe APK path (`probe_apk`; for `.xapk` the base/main
split). Add:

```python
import zipfile
def _probe_engine(apk: Path) -> str | None:
    try:
        with zipfile.ZipFile(apk) as zf:
            return probe_engine_from_names(zf.namelist())
    except (OSError, zipfile.BadZipFile):
        return None
```

Call it inside the existing `working_tmp_dir` block (the probe APK is already on
disk there) and add one row to `_print_info`'s `rows`:

```python
("engine", engine or 'unknown'),
```

Insert after `version` (matches report header order, where engine follows version).

### Limitation (document in code)

For a `.xapk`, only the **base** APK's namelist is probed. If a Unity game ships
`libil2cpp.so` only in an arch-split APK (DENarrow / Play Asset Delivery) and has no
`assets/bin/Data/**` in the base, the probe may miss it. Acceptable for a triage
command; full multi-split detection stays in `analyze`. Note this in the helper
docstring.

### Verify

- `dumpa info Township/com.playrix.township.xapk` → `engine  Unity`
- `dumpa info Arrows/com.ecffri.arrows.apk` → engine row present (Unity or `unknown`)
- Unit test `probe_engine_from_names(["lib/arm64-v8a/libil2cpp.so"]) == "Unity"`,
  `["assets/flutter_assets/x"] == "Flutter"`, `[] is None`.

---

## 2. debug-cert detection

### Signal

The Android debug keystore generates a **per-machine key**, so the cert SHA-256 is
not fixed — but the certificate **DN is constant**: `CN=Android Debug, O=Android, C=US`.
`apksigner verify --print-certs` already emits a `Signer #N certificate DN:` line; the
current parser (`tools/apksigner.py`) just doesn't capture it.

### `tools/apksigner.py`

Add a DN regex and a derived `is_debug` flag on `SignerInfo`:

```python
_CERT_DN_RE = re.compile(r'certificate DN:\s*(.+)')
_DEBUG_DN_PARTS = frozenset({"cn=android debug", "o=android", "c=us"})

@dataclass(frozen=True)
class SignerInfo:
    cert_sha256: str | None
    schemes: tuple[str, ...]
    is_debug: bool = False          # DN == the canonical Android debug DN
```

In `parse_verify_output`:

```python
dn_match = _CERT_DN_RE.search(text)
is_debug = False
if dn_match:
    parts = {p.strip().lower() for p in dn_match.group(1).split(",")}
    is_debug = _DEBUG_DN_PARTS <= parts
```

Set-of-RDN comparison is order- and spacing-insensitive (apksigner output ordering
varies). `is_debug` defaults `False` so existing constructions and unsigned text stay
valid.

### `core/report.py` — `AppFacts`

Add one field, keeping the `signer_*` cluster together:

```python
signer_is_debug: bool | None = None   # signed with the Android debug certificate
```

Thread through `to_dict` (`"signer_is_debug": self.signer_is_debug`) and `from_dict`
(`signer_is_debug=data.get("signer_is_debug")`). Add a Markdown render row near the
existing signer rows; mirror in `render_html` if it renders signer facts.

### Population — two call sites

- **`commands/info.py`**: `_read_signer` already returns `SignerInfo`; add a row
  `("debug cert", _flag(signer.is_debug))` to `_print_info` (only meaningful when
  signed). Use a yes/no/`?` rendering consistent with existing flag rows.
- **`reporting.build_report`**: wherever `signer_cert_sha256`/`signing_schemes`
  populate `AppFacts`, also set `signer_is_debug=signer.is_debug`. (Confirm
  `build_report` parses signer output via the same `apksigner.parse_verify_output`;
  if it reads schemes/cert it already has the `SignerInfo` in hand.)

### Verify

- `dumpa info ManorCafe/app-debug.apk` → `debug cert  yes`
- `dumpa info ManorCafe/ManorCafe_1230047.apk` → `debug cert  no` (release signer)
- Unit test `parse_verify_output` on a captured `--print-certs` debug sample →
  `is_debug is True`; on a release sample → `False`; on `""` → `False`.

---

## 3. tracker taxonomy gaps (data-only)

### Scope

Three taxonomy categories are unimplemented (ROADMAP Phase 5): **A/B testing**,
**anti-fraud**, **consent management**. `category` is a free-string attribute on
tracker rules (`rules/trackers.toml`), consumed by reporting/diff as data — **confirm
no enum gating** in `core/rules.py` before adding (grep for a category allowlist; if
one exists, extend it). No code change otherwise; add `[[rule]]` blocks and bump
`[bundle].version`.

### Rules to add (well-known SDKs, class-path matchers)

```toml
# --- A/B testing -------------------------------------------------------------
# (Firebase A/B Testing rides Remote Config, already detected — not duplicated.)
Optimizely          category="A/B testing"  owner="Optimizely"   strings=["com/optimizely"]
LaunchDarkly        category="A/B testing"  owner="LaunchDarkly" strings=["com/launchdarkly"]
Amplitude Experiment category="A/B testing" owner="Amplitude"    strings=["com/amplitude/experiment"]

# --- anti-fraud --------------------------------------------------------------
Forter              category="anti-fraud"   owner="Forter"       strings=["com/forter"]
Sift                category="anti-fraud"   owner="Sift"         strings=["com/sift", "com/siftscience"]
Arkose Labs         category="anti-fraud"   owner="Arkose Labs"  strings=["com/arkoselabs"]
FingerprintJS       category="anti-fraud"   owner="FingerprintJS" strings=["com/fingerprintjs"]

# --- consent management ------------------------------------------------------
OneTrust            category="consent management" owner="OneTrust"   strings=["com/onetrust"]
Google UMP          category="consent management" owner="Google"     strings=["com/google/android/ump"]
Didomi              category="consent management" owner="Didomi"      strings=["io/didomi"]
Sourcepoint         category="consent management" owner="Sourcepoint" strings=["com/sourcepoint"]
Quantcast Choice    category="consent management" owner="Quantcast"   strings=["com/quantcast"]
```

(Full `[[rule]]` form: `kind="tracker"`, `confidence="high"`, plus the fields above —
match the existing block shape in `trackers.toml`.)

### Notes

- Class-path containment dedup with `trackers_exodus` is already handled by the Exodus
  importer (curated stays authoritative). New curated rules need no special handling.
- `Google UMP` owner `Google` — verify the domain-attribution single-owner fallback in
  `enrich_domain_attribution` (only attributes when exactly one tracker per owner) is
  not surprised by another Google consent entry; `category` differs but owner collides
  with many Google trackers, so this is fine (fallback already guards `len==1`).

### Verify

- A scan over a sample bundling OneTrust → finding `category="consent management"`.
- `dumpa rules explain tracker "OneTrust"` shows the new rule.
- Roadmap Phase 5 taxonomy checkboxes flip to `[x]`.

---

## 4. diff: changed native symbols (+ shared `diff` refactor)

### Problem

`core/diff.py` diffs **report findings** by `(kind, subject)`. Native symbols are not
in the report — `scanners/native.py` writes full export/import lists to sidecars
`dumps/native/<abi>__<lib>.json` and keeps only counts in the finding. And
`report_for_input` (`commands/analyze.py`) discards its ephemeral workspace, so the
sidecars vanish before diff can read them.

### Shared refactor — live workspaces for diff

Replace the report-only path with a context manager that keeps the workspace alive:

```python
# commands/analyze.py
@contextmanager
def open_for_diff(input_path: Path) -> Iterator[tuple[Workspace, Report]]:
    """Yield a populated workspace + its report; for apk/xapk inputs the workspace
    is an ephemeral extraction kept open for the duration (so sidecars are readable)."""
    config = load_config(); registry = build_default_registry(config.tool_paths)
    input_abs = input_path.resolve()
    if input_abs.is_dir():
        ws = Workspace(root=input_abs)
        if ws.read_meta() is None:
            raise DumpaError(...)
        yield ws, build_report(registry, ws)
        return
    in_type = input_type(input_abs)
    if in_type == "xapk":
        prepare_convert(registry, None)
    with open_workspace(None) as ws:
        build_workspace(registry, ws, input_abs, in_type, sha256_file(input_abs), None)
        yield ws, build_report(registry, ws)   # build_report runs native.scan → writes sidecars
```

`report_for_input` can be reimplemented on top of this (or kept for `load`); the diff
command switches to `open_for_diff`. Note `build_report` runs `native.scan`, which
writes the sidecars into the (still-open) workspace — so they exist when diff reads
them.

### `core/diff.py` — native symbol diff

```python
@dataclass(frozen=True)
class NativeSymbolDelta:
    lib: str                     # "<abi>/<name>.so"
    exports_added: list[str]
    exports_removed: list[str]
    imports_added: list[str]
    imports_removed: list[str]
    @property
    def changed(self) -> bool: ...

def diff_native_symbols(old_ws: Workspace, new_ws: Workspace) -> list[NativeSymbolDelta]:
    """Per-lib export/import set diff from each workspace's dumps/native/*.json sidecars."""
```

- Read `*.json` sidecars from `old_ws.native_dir` / `new_ws.native_dir` (keys:
  `exports[].name`, `imports[].name`).
- Match libs by sidecar filename (`<abi>__<lib>.json`); a lib present in only one side
  → all-added or all-removed.
- Set-diff names; emit a `NativeSymbolDelta` only when something changed. Sort names.
- Symbol counts are large but bounded by symbol count, not file size; sets of strings.
  No file is streamed (sidecars are already-compact JSON).

### Rendering

`render_diff` is report-only; add native symbols as a separate section composed by the
command (keeps `diff_reports` pure). Either:
- extend `render_diff` signature with optional `native: list[NativeSymbolDelta]`, or
- add `render_native_symbol_diff(deltas) -> str` and concatenate in the command.

Prefer a separate renderer + a `render_full_diff` stitcher, so each `core/diff.py`
function stays single-purpose and unit-testable. Section shape:

```
## native symbols
arm64-v8a/libil2cpp.so
  exports +12 / -3
    + il2cpp_new_export
    ...
  imports +1 / -0
    + dlopen
```

Large symbol lists: render counts always; list names with a display cap (e.g. 200 per
group) and a `... (+N more)` overflow line. The cap is display-only — the model carries
the full lists for programmatic consumers.

### Verify

- `dumpa diff ManorCafe/ManorCafe_1230047.apk ManorCafe/patched_ManorCafe_1230047.apk`
  → native-symbols section (likely empty/small for a smali-only patch — a good
  no-false-positive check).
- Unit: two synthetic sidecar dirs with a renamed export → one `NativeSymbolDelta`
  with the rename as `+new` / `-old`.

---

## 5. diff: changed Unity methods (full method-set)

### Inputs

Needs `dumps/dump.cs` in **both** workspaces. `build_report` does **not** auto-dump
il2cpp (that is `analyze`'s `_maybe_autodump`, command-level). So:
- workspace inputs that were produced by `analyze` (auto-dump on) → `dump.cs` present.
- bare apk/xapk inputs via `open_for_diff` → no `dump.cs`; **skip with a note**.

This is therefore primarily a workspace-vs-workspace feature. Document it; do not
auto-dump inside diff (dumping a 195 MB game twice in a diff is too heavy and
surprising).

### `core/dumpcs_methods.py` (new) — streaming method extraction

```python
def iter_method_sigs(dump_cs: Path) -> Iterator[str]:
    """Yield stable 'Namespace.Class::MethodSignature' identities from an Il2CppDumper
    dump.cs, streaming line-by-line. RVA/Offset/VA comments are ignored (they change
    every build); identity is class context + method declaration only."""
```

- Stream the file (bounded memory — never read whole; respects the Architecture
  Foundations streaming rule). Reuse the chunked/line reader the dumpcs scanner uses if
  one is exposed; otherwise iterate the file object line by line.
- Track current type context from `class`/`struct`/`enum` declaration lines.
- Recognize method declaration lines (return-type + name + `(params)`); strip the
  trailing `{ }` and any `// RVA: ... Offset: ...` comment.
- Emit `Class::ReturnType Name(paramTypes)` — a signature stable across rebuilds.
  Exclude addresses so unchanged methods compare equal between versions.
- Parser must fail-soft on malformed lines (skip, don't raise).

The resulting **set** of signature strings is bounded by method count (~10^5 for a big
game ≈ a few MB of strings) — safe to hold two in memory; the *file* is never fully
loaded.

### `core/diff.py` — method diff

```python
@dataclass(frozen=True)
class MethodDelta:
    added: list[str]
    removed: list[str]
    @property
    def changed(self) -> bool: ...

def diff_unity_methods(old_ws: Workspace, new_ws: Workspace) -> MethodDelta | None:
    """Set-diff of dump.cs method signatures. None when either dump.cs is absent."""
```

- Return `None` (caller renders a skip note) if either `dumps/dump.cs` is missing.
- Build both sets via `iter_method_sigs`, set-diff, sort.

### Gating + rendering

- Gate on engine: only compute/render when `new_report.facts.engine == "Unity"`
  (Il2CppDumper output is Unity-specific). The command has the report from
  `open_for_diff`.
- Render section (separate renderer, like §4):

```
## unity methods
  + GameManager::Void SpawnEnemy(Int32)
  - GameManager::Void SpawnEnemy()
  ... (+N more)
```

- Display cap as in §4 (counts always; capped name lists). Counts can be in the
  thousands — the cap keeps terminal output usable; the model keeps full lists.

### Verify

- Two `analyze`-produced workspaces of consecutive ManorCafe/Township versions →
  non-empty added/removed.
- Bare apk inputs → method section shows `no dump.cs in <input>; run analyze first`.
- Unit: two synthetic `dump.cs` fixtures (a few classes, one method added/renamed,
  differing RVA comments on identical methods) → only the real add/rename in the delta,
  RVA-only changes produce **no** diff (proves address-stripping works).

---

## Cross-cutting

- **Ordering**: 1 → 2 → 3 land independently and fast. 4 introduces the `open_for_diff`
  refactor; 5 builds on it. Land 4 before 5.
- **No new dependencies.** `zipfile`, `re`, `json`, stdlib streaming only.
- **Caching**: items 1–3 don't touch the scanner cache. Taxonomy additions (3) bump
  `trackers.toml` `[bundle].version`, which is part of the tracker scanner's cache key
  (`SCANNERS` registration), so cached tracker results invalidate correctly on update.
- **Tests** run against `/apk/apk/Games` samples (Township xapk, ManorCafe variants,
  Arrows) plus synthetic fixtures for the parsers (sidecar JSON, dump.cs snippets,
  apksigner output). Keep apk-dependent tests opt-in/skippable if samples are absent in
  CI, matching the existing golden-sample posture (ROADMAP: real-apk golden sample
  still pending).
- **Roadmap checkboxes flipped** on completion: Phase 1 `info` engine; Phase 1 debug-cert;
  Phase 5 taxonomy (A/B, anti-fraud, consent); Phase 10 changed native symbols + changed
  Unity methods; and `info` engine note in Core Capabilities.

### Out of scope (explicit)

- radare2 region scanning, cross-reference index, Data Safety comparison — separate,
  larger efforts (see the brainstorm brief).
- Auto-dumping il2cpp inside `diff` (too heavy; method diff stays workspace-first).
- Multi-split engine detection for `info` (base-apk namelist only).
