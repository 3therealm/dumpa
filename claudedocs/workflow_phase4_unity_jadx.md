# Workflow — Phase 4 Unity Depth + JADX Wiring

TDD implementation plan derived from `docs/design-phase4-unity-jadx.md`. Plan only —
no code here. Execute with `/sc:implement`.

**Strategy:** systematic, test-first. Each step lands red → green → refactor, every
suite green before the next step. **No tracker-SDK overlap** in `unity.toml`. JADX output
is an artifact (sidecar provenance), **not** scanner findings — no cache-layer change.

**Branch:** already on `feat/phase-1-workspace`. Recommend a feature branch
`feat/phase-4-unity-jadx` off `main` before starting (confirm with user).

---

## Dependency graph

```
S1 rules/unity.toml ─┐
                     ├─► S2 unity_rules scanner ─┐
                     │                            ├─► S4 gate wiring (run_all) ─► S6 ROADMAP flips
S3 unity_assets ─────┘ (independent of S1/S2) ───┘
S5 JADX (decompile cmd + analyze flag) ── independent ──────────► S6
```

- **S1 → S2 → S4** is the critical path (bundle, then its scanner, then the gate).
- **S3** (Addressables code scanner) depends only on the Finding model — parallelizable
  with S1/S2.
- **S5** (JADX) is fully independent — can be built first, last, or in parallel.
- **S6** (ROADMAP checkbox flips + final verify) is last, gated on S2/S3/S4/S5 verified.

Suggested order: **S1 → S2 → S3 → S4 → S5 → S6** (one PR, or split S5 into its own PR).

---

## Step 1 — `rules/unity.toml` bundle

**Goal:** a versioned built-in bundle of Unity-integration markers, auto-discovered by
`load_builtin("unity")`, with **zero overlap** against `trackers.toml`.

**Files**
- `src/dumpa/rules/unity.toml` (new)
- `tests/test_rules.py` or new `tests/test_unity_bundle.py` (extend)

**Tasks**
1. Author `[bundle]` header (`name="unity"`, version, source, updated).
2. Rules per design §2.2: Unity services (`content` class-paths), Unity + Firebase
   Remote Config (`content`), Firebase config residue (`content` over `res/values/**`),
   Firebase libs (`path_glob`), Addressables presence (`path_glob`), Unity native
   plugins (`path_glob`, non-tracker libs only). All `kind="engine-detail"`.
3. Set `confidence`/`state` per design (high for lib/class path; medium for bare
   res-strings; `referenced` for dex class-path hits).

**Verify (TDD)**
- `load_builtin("unity")` parses without `ConfigError`.
- `builtin_bundle_names()` includes `"unity"`; `dumpa rules list` shows it.
- **Overlap guard test:** assert no rule subject/key in `unity.toml` collides with a
  tracker SDK owned by `trackers.toml` (cross-bundle dedup assertion).
- `pytest tests/test_rules.py tests/test_unity_bundle.py` green.

**Checkpoint:** bundle loads, listed, no tracker overlap.

---

## Step 2 — `unity_rules` scanner (Unity-gated bundle application)

**Goal:** a 1-line scanner applying the `unity` bundle, mirroring `scanners/engine.py`.

**Files**
- `src/dumpa/scanners/unity_rules.py` (new)
- `tests/test_scanners.py` (extend, reuse `_ws`/`_touch` helpers)

**Tasks**
1. `scan(ws)` → guard `ws.extracted_dir.is_dir()`; return
   `apply_bundle(load_builtin("unity"), ws.extracted_dir, load_manifest(ws))`.

**Verify (TDD)**
- Synthetic tree with `res/values/strings.xml` containing `google_app_id` → a
  `Firebase config` finding (medium).
- Dex blob containing `com/unity3d/services/analytics` → `Unity service: Analytics`
  finding (`referenced`).
- `lib/arm64-v8a/libFirebaseCppApp.so` → `Firebase native runtime` (high).
- `assets/aa/catalog.json` present → `Unity Addressables catalog` (high).
- Empty/non-Unity tree → `[]`.
- AppLovin-only tree (tracker SDK) → no duplicate Unity-plugin finding.

**Checkpoint:** scanner emits expected `engine-detail` findings on fixtures.

---

## Step 3 — `unity_assets` scanner (Addressables remote-URL attribution)

**Goal:** parse `assets/aa/**/catalog*.json`, attribute http(s) internal-ids as
Addressables remote content endpoints. Self- + Unity-gated; bounded streaming.

**Files**
- `src/dumpa/scanners/unity_assets.py` (new)
- `tests/test_unity_assets.py` (new)

**Tasks**
1. `scan(ws)` no-op unless a catalog JSON exists under `assets/aa/`.
2. Bounded parse of the internal-id list (`m_InternalIds` / `InternalIdList`); collect
   distinct http(s) URLs.
3. Emit `Finding(kind="engine-detail", subject="Addressables remote content: <host>",
   state="referenced", evidence=[Evidence(snippet=url, tool="unity")],
   locations=[Location(file_path=<catalog rel>)])` per host.

**Verify (TDD)**
- Catalog with a remote `https://cdn.example.com/...` id → one finding for that host.
- Catalog with only local ids → `[]`.
- Missing `assets/aa/` → `[]`.
- Large synthetic catalog → bounded memory (no whole-file load; mirror endpoint-scanner
  streaming assertion style).
- Downstream: emitted host flows through `enrich_domain_attribution` (assert attribution
  when the host is in the domains table).

**Checkpoint:** Addressables URLs surface as attributed `engine-detail` findings.

---

## Step 4 — Wire the Unity gate (`run_all`)

**Goal:** generalize the single `UNITY_SPEC` to a looped `UNITY_SPECS` tuple under the
existing `engine/Unity` gate.

**Files**
- `src/dumpa/scanners/__init__.py` (edit §5 of design)
- `tests/test_scanners.py` (extend `run_all` coverage)

**Tasks**
1. Define `UNITY_SPECS = (UNITY_SPEC, ScannerSpec("unity_rules", unity_rules.scan,
   ("unity",)), ScannerSpec("unity_assets", unity_assets.scan))`.
2. In `run_all`, replace the single-spec gate body with a loop over `UNITY_SPECS`.
3. Confirm `unity_rules` cache-keys on the `unity` bundle version (via `bundles=`);
   `unity_assets` keys on dumpa version (empty bundles).

**Verify (TDD)**
- `run_all` on a Unity fixture includes `unity_rules` + `unity_assets` findings.
- `run_all` on a non-Unity fixture runs **none** of `UNITY_SPECS` (gate holds).
- Editing `unity.toml` version busts the `unity_rules` cache (extend `test_cache.py`
  pattern); re-run recomputes.

**Checkpoint:** full `analyze` pipeline surfaces Unity-detail findings, gated correctly.

---

## Step 5 — JADX wiring (`dumpa decompile` + `analyze --jadx`)

**Goal:** read-only, on-demand JADX decompile to a workspace artifact with provenance
sidecar. Independent of S1–S4.

**Files**
- `src/dumpa/commands/decompile.py` (new)
- `src/dumpa/cli.py` (add `decompile` command; add `--jadx` to `analyze`)
- `src/dumpa/commands/analyze.py` (optional post-analysis JADX step)
- `tests/test_decompile.py` (new)

**Tasks**
1. `decompile(input, *, workspace, selector, out)`:
   - Resolve `jadx` via registry; `ToolNotFoundError` → log warning, return (exit 0).
   - Enforce on-demand: require `--class` / `--package` / `--all`; no selector → usage
     error.
   - `--class a.b.C` → `jadx --single-class a.b.C -d <out>`.
   - `--package a.b` → decompile to `<out>`, retain only `sources/<pkg path>/`
     *(confirm filter-after vs per-class during impl)*.
   - Write `<out>/.dumpa-decompile.json` = `{tool, version, selector, input_sha256}`;
     skip re-run when a matching sidecar exists.
   - Default `--out` = `<workspace>/decompiled/`.
2. CLI: `@app.command()` `decompile` (input arg, `--class/--package/--all`, `--out`,
   `--workspace`), wrapped in `run_command`.
3. `analyze --jadx`: post-analysis, decompile the app's own package (manifest `package`
   attr) as the default selector; JADX absent → warn + skip, analysis still succeeds.

**Verify (TDD)**
- Registry override → `jadx` points at a stub script; `--class` builds argv with
  `--single-class` + output dir; sidecar written with stub version.
- Nonexistent `jadx` → warning, exit 0, no crash.
- No selector (and not `--all`) → usage error (nonzero).
- `analyze --jadx` with jadx absent → analysis completes, warning logged.
- Re-run with matching sidecar → skips invocation.

**Checkpoint:** decompile works on-demand, degrades gracefully when jadx absent.

---

## Step 6 — ROADMAP flips + full verification

**Goal:** flip only verified checkboxes; full-suite green.

**Files**
- `ROADMAP.md` (edit per design §10)

**Tasks**
1. Flip Phase 4 Unity helpers (plugin/Plugins-Android/services/Addressables/Firebase/
   remote-config) → `[x]`, with the APK-merge note on the plugin items.
2. Phase 4 engine config-file parser `[~]` → addressed.
3. Phase 8 JADX `[~]` → `[x]`; baksmali `[~]` → `[x]` *satisfied by apktool*.
4. Run full suite + lint.

**Verify**
- `pytest` (full ~104+ suite + new tests) green.
- `ruff`/type-check clean (match repo config).
- `dumpa rules list` shows `unity`; `dumpa decompile --help` and `dumpa analyze --help`
  show new surfaces.
- Manual smoke (if a Unity sample is available): `dumpa analyze <unity.apk>` report
  contains `engine-detail` Unity findings; `dumpa decompile <apk> --class <known.Class>`
  produces output + sidecar.

**Checkpoint:** feature complete, suite green, ROADMAP accurate.

---

## Quality gates (per step)

| Gate | Check |
|------|-------|
| Tests-first | failing test written before impl each step |
| No regression | full `pytest` green before advancing |
| No tracker overlap | S1 cross-bundle dedup assertion |
| Gate integrity | S4 non-Unity ⇒ zero Unity-spec findings |
| Graceful optional tool | S5 jadx-absent ⇒ warn + exit 0 |
| Bounded memory | S3 large-catalog streaming assertion |
| Reproducibility | S5 sidecar provenance; S4 bundle-version cache bust |

## Risks / open impl details (resolve during `/sc:implement`)

1. **`--package` filtering** — JADX has no native package-include. Filter-after-decompile
   (simpler, heavier) vs. per-class loop (lighter, more invocations). Confirm.
2. **Addressables catalog schema** — `m_InternalIds` key/shape varies across Unity
   Addressables versions; the parser must tolerate schema drift (fall back to a bounded
   URL regex over the catalog rather than failing).
3. **Unity service class-paths** — validate the exact `com/unity3d/services/*` substrings
   against a real Unity build before locking confidence/state.
4. **`analyze --jadx` default scope** — app-package default may still be large; consider
   logging the artifact size and leaving full control to `dumpa decompile`.

## Next step

`/sc:implement` — execute S1→S6 in order, TDD per step.
