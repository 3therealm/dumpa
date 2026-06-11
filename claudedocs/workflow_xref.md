# Workflow: Cross-Reference Index (Phase 7)

Implementation plan for `docs/design/xref.md`. TDD-first, dependency-ordered. Plan only —
no code here. Execute with `/sc:implement` step by step.

**Strategy:** systematic · **Depth:** deep
**Outcome:** `dumpa xref` standalone command + `dumps/xref.json` artifact; flips Phase 7
`[ ] cross-reference index` → `[x]`.

## Dependency graph

```
P1 core/jni.py            (leaf, pure)
        │
P2 core/xref.py model + normalize + layer_of   (depends: report.Location, dex helper)
        │
P3 core/xref.py build_xref + query_xref         (depends: P1, P2, sidecars, dumpcs_methods, manifest)
        │
P4 core/xref.py renderers (text + json) + to_dict/from_dict + Workspace.xref_sidecar
        │
P5 commands/xref.py + cli.py wire               (depends: P3, P4, analyze.open_for_diff)
        │
P6 analyze --xref flag + report compact line    (depends: P3, P4)  [optional, parallel-able after P4]
        │
P7 ROADMAP flip + doctor/help docs              (depends: P5)
```

P6 is independent of P5 once P4 lands (both consume P3/P4); may run in parallel.

---

## Phase 1 — JNI decoder (`core/jni.py`)

Leaf, pure, no workspace. Build first so the native↔dex join in P3 has its dependency.

- **1.1** `decode_jni(symbol) -> tuple[str, str] | None` per design §5.
  - verify: tests below pass.
- **1.2** Tests (`tests/test_jni.py`, table-driven):
  - `Java_com_foo_Bar_method` → `("com.foo.Bar", "method")`
  - escapes: `_1`→`_`, `_2`→`;`, `_3`→`[`, `_0XXXX`→unicode char
  - overload signature: `Java_..._m__II` → strip `__II`, class+method correct
  - non-JNI (`abc`, `JavaCritical_*`, no prefix) → `None`
  - malformed/truncated escape → `None` (never raises)
  - verify: `pytest tests/test_jni.py` green.

**Checkpoint P1:** decoder green in isolation, zero deps imported beyond stdlib.

---

## Phase 2 — Model + pure helpers (`core/xref.py`)

No I/O yet — types and the two pure functions everything keys on.

- **2.1** Enums `EntityType`, `Layer`; dataclasses `Appearance`, `XrefEntity`
  (`.layers` property), `XrefProvenance`, `Xref` (design §2). Frozen, same style as
  `report.py`.
- **2.2** `normalize(entity_type, raw) -> str` (design §3): domain fold; class
  descriptor→dotted (reuse `dex._descriptor_to_dotted`, smali `/`→`.`); string/symbol
  pass-through.
- **2.3** `layer_of(file_path) -> Layer | None` (design §6), all branches + None.
- **2.4** Tests (`tests/test_xref_model.py`):
  - `normalize`: each type's case rule; `Lcom/foo/Bar;`→`com.foo.Bar`; domain uppercase→fold.
  - `layer_of`: manifest / smali / .dex / decompiled / .so / dump.cs / res / resources.arsc
    / assets / dumps-cocos / dumps-godot / unknown→None.
  - `XrefEntity.layers` dedups across appearances.
  - verify: `pytest tests/test_xref_model.py` green.

**Checkpoint P2:** model + normalization + layer mapping fully unit-covered, still I/O-free.

---

## Phase 3 — Builder + query (`core/xref.py`)

The core. Two-pass streaming build + single-entity query (design §4, §7).

- **3.1** Source iterators (internal generators yielding `(EntityType, raw_key, Layer,
  Location)`):
  - findings: subject + each Location (domain/dex_class/manifest_entry) + matched-string
    evidence snippet → STRING; layer via `layer_of(location.file_path)` (manifest_entry
    with no path → MANIFEST).
  - native sidecars `dumps/native/*.json` → SYMBOL (exports+imports), NATIVE, RVA from `rva`.
  - dex sidecars `dumps/dex/*` → CLASS, SMALI.
  - manifest (`core/manifest.load_manifest`) → CLASS components, MANIFEST.
  - dump.cs methods (`core/dumpcs_methods`, **streamed**) → CLASS declaring type, DUMPCS.
- **3.2** JNI alias merge: SYMBOL `Java_*` → `decode_jni` → emit alias to that CLASS key.
- **3.3** `build_xref(ws, findings, *, built) -> Xref`:
  - pass 1 tally `dict[(type,key), set[Layer]]`;
  - pass 2 materialize appearances **only** where `len(layerset) >= 2`;
  - `layers_present` + `deferred=("cpp-demangle","resource-enumeration")` into provenance;
  - `built` is passed in (no `Date` in core).
- **3.4** `query_xref(ws, findings, entity, *, case_insensitive=False) -> XrefEntity | None`
  — one streaming pass, matches normalized key across types, answers single-layer too.
- **3.5** Tests (`tests/test_xref_build.py`, in-memory `Workspace` + synthetic
  findings/sidecars):
  - domain seeded in native + smali + manifest → one entity, 3 appearances, layers={3}.
  - `Java_*` symbol joins its dex class (alias edge present, NATIVE appearance under CLASS).
  - single-layer entity **excluded** from `build_xref` output.
  - `query_xref` **finds** that single-layer entity.
  - `case_insensitive` folds a string match.
  - dump.cs iterated via streaming path, not loaded whole (assert through
    `dumpcs_methods` seam / large synthetic file).
  - empty/missing sidecars → no crash, `layers_present` reflects what existed.
  - verify: `pytest tests/test_xref_build.py` green.

**Checkpoint P3:** build + query correct on synthetic workspace; memory bounded; missing
layers degrade cleanly.

---

## Phase 4 — Serialization + renderers + workspace accessor

- **4.1** `Xref.to_dict/from_dict` + JSON read/write (round-trip), `report.py` style.
- **4.2** `Workspace.xref_sidecar` property → `dumps_dir / "xref.json"`.
- **4.3** Freshness: `build_xref` no-arg path reuses `xref.json` when
  `provenance.input_sha256 == meta.input_sha256` unless `--no-cache` (design §9).
- **4.4** Renderers `render_xref_list(xref, min_layers)` + `render_xref_entity(entity)`
  (text) and a `--json` path — split like `core/diff.py` (`*_diff` + `render_*`).
- **4.5** Tests: JSON round-trip equality; freshness reuse vs sha-mismatch rebuild;
  renderer snapshot (list + single-entity).
  - verify: `pytest tests/test_xref_serialize.py` green.

**Checkpoint P4:** artifact persists, reloads identically, freshness guard works.

---

## Phase 5 — CLI (`commands/xref.py` + `cli.py`)

- **5.1** `commands/xref.py::xref(workspace, entity=None, min_layers=2,
  case_insensitive=False, json_=False, out=None, no_cache=False)`:
  - dir → existing ws (require `read_meta`); apk/xapk → reuse `analyze.open_for_diff`.
  - no entity → `build_xref` + persist + `render_xref_list`.
  - entity → `query_xref` + `render_xref_entity` (or "not found").
  - `--json`/`--out` honored.
- **5.2** Wire in `cli.py` (`import xref as xref_cmd`, `@app.command()` mirroring `diff`).
- **5.3** Tests (`tests/test_cli_xref.py`, Typer `CliRunner`):
  - list view on a built workspace (≥2-layer rows present, `--min-layers 3` filters).
  - single-entity view prints appearances; unknown entity → graceful message, nonzero/zero
    exit per convention.
  - non-workspace dir → clear error (mirror `open_for_diff` message).
  - verify: `pytest tests/test_cli_xref.py` green.

**Checkpoint P5:** `dumpa xref <ws>` and `dumpa xref <ws> <entity>` work end-to-end.

---

## Phase 6 — analyze + report integration (optional, parallel after P4)

- **6.1** `analyze --xref` flag → after scanners, build + persist `dumps/xref.json`.
- **6.2** `reporting.build_report` reads the artifact if present → one compact line
  `cross-layer correlations: N (dumps/xref.json)`; no inlined findings.
- **6.3** Tests: `analyze --xref` writes the artifact; report line appears when present,
  absent otherwise.
  - verify: `pytest -k xref_analyze` green.

**Checkpoint P6:** opt-in integration; default analyze unchanged (no extra dump.cs pass).

---

## Phase 7 — Docs + roadmap

- **7.1** `ROADMAP.md`: Phase 7 `[ ] cross-reference index` → `[x]` with the same
  parenthetical-evidence style as neighbors; note deferred (cpp-demangle, resource
  enumeration). Add `dumpa xref` to Command Ideas.
- **7.2** Help text / README command list if one exists.
- **7.3** Full suite: `pytest` green; `dumpa doctor` unaffected.
  - verify: whole suite green, manual `dumpa xref` smoke on a real workspace.

**Checkpoint P7:** roadmap reflects shipped state; suite green.

---

## Global validation gates

- Every phase: new tests green **before** moving on (TDD).
- No new third-party deps (stdlib only) — grep imports in `core/jni.py`, `core/xref.py`.
- Memory: dump.cs streamed, never loaded whole — assert via `dumpcs_methods` seam.
- Surgical: no edits outside the new files + `cli.py` + (P6) `analyze.py`/`reporting.py` +
  (P7) `ROADMAP.md`/`workspace.py` accessor.

## Risks / watch-items

- **dump.cs class extraction** — `dumpcs_methods` yields method signatures; confirm it
  exposes the **declaring type** for the CLASS/DUMPCS appearance, else add a thin
  type-extraction helper there (small, in-scope) rather than re-parsing dump.cs.
- **JNI boundary ambiguity** — overloaded/`_`-heavy names; class join is the payoff, so
  bias the decoder to get the **class** right even if method is approximate.
- **dex sidecar shape** — verify `dumps/dex/*` actually carries class names at build time
  (roadmap says inventory exists); if a run hasn't produced it, `layers_present` must omit
  SMALI rather than error.

## Execution order summary

P1 → P2 → P3 → P4 → (P5 ∥ P6) → P7.
Smallest shippable slice: P1–P5 (command works); P6 is additive; P7 closes the roadmap.
