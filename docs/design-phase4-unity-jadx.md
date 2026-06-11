# Design — Phase 4 Unity Depth + JADX Wiring

Scope locked in brainstorm: complete the Phase 4 Unity deep-helper items and wire
JADX (Phase 8). Decisions carried in: JADX gets **both** a `dumpa decompile` command
and an `analyze --jadx` flag; JADX is **on-demand** (selector-driven, never full-APK by
default); baksmali is **satisfied-by-apktool** (checkbox flip, no new invocation); Unity
services/Firebase/remote-config/plugin/Addressables-presence detection ships as a
**`rules/unity.toml` bundle**; only Addressables remote-URL extraction needs **scanner
code**. Cocos/Godot deferred.

This is design only — no implementation. Next step: `/sc:implement` or `/sc:workflow`.

---

## 1. Architectural fit

Every capability here plugs into existing seams; no new subsystem.

- **Rule bundles** are the detection substrate (`core/rules.py`). A bundle is
  `[bundle]` + `[[rule]]` tables; `load_builtin(name)` auto-discovers any
  `rules/<name>.toml` (prefers a user override under `$XDG_CONFIG_HOME/dumpa/rules/`).
  `apply_bundle(bundle, extracted_dir, manifest)` returns `list[Finding]`. The
  `path_glob`, `content` (strings/regex over files), and `manifest` matcher kinds
  already cover everything the Unity bundle needs.
- **Scanners** are pure `scan(ws) -> list[Finding]`, registered in
  `scanners/__init__.py:SCANNERS`, memoized by `core/cache.py`.
- **The Unity gate** already exists: `run_all` runs the global `SCANNERS`, then — only
  when an `engine`/`Unity` finding is present — runs `UNITY_SPEC` (`scanners/unity.py`).
  All new Unity work hangs off this gate, so it is a guaranteed no-op on non-Unity apps.

Reality check that shapes the design: **a built APK has no `Assets/Plugins/Android/`
tree.** Unity merges that content at build time into native libs (`lib/<abi>/*.so`),
the merged `AndroidManifest.xml`, and resources. So "Plugins/Android scanner" and
"plugin scanner" both resolve to **native-lib + manifest marker detection**, not a
directory walk. The design reflects this.

---

## 2. Component A — `rules/unity.toml` (new built-in bundle)

A versioned bundle, one rule per known marker. Auto-discovered by
`builtin_bundle_names()`; surfaced by `dumpa rules list`; refreshable later by
`update-signatures`. Consumed by a thin Unity-gated scanner (Component B).

### 2.1 Bundle header

```toml
[bundle]
name = "unity"
version = "2026.06.1"
source = "dumpa built-in"
updated = "2026-06-08"
```

### 2.2 Rule groups (matcher kind in parens)

| Group | Matcher | Keys on | Example subject |
|-------|---------|---------|-----------------|
| Unity services (`content`) | dex/.so class-path substrings | `com/unity3d/services/analytics`, `com/unity3d/services/banners`, `com/unity3d/ads`, `com/unity3d/services/store` (IAP), `com/unity3d/services/core` (UGS) | `Unity service: Analytics` |
| Unity Remote Config (`content`) | class-path | `com/unity3d/services/remoteconfig`, `Unity.Services.RemoteConfig` | `Unity Remote Config` |
| Firebase config (`content`) | res-string keys | `google_app_id`, `gcm_defaultSenderId`, `firebase_database_url`, `google_api_key` over `res/values/**` | `Firebase config (google-services residue)` |
| Firebase libs (`path_glob`) | native libs | `lib/*/libFirebaseCppApp*.so`, `lib/*/libgoogle*.so` | `Firebase native runtime` |
| Firebase Remote Config (`content`) | class-path | `com/google/firebase/remoteconfig` | `Firebase Remote Config` |
| Addressables presence (`path_glob`) | catalog files | `assets/aa/**/catalog*.json`, `assets/aa/**/settings.json`, `**/aa/catalog*.bundle` | `Unity Addressables catalog` |
| Unity native plugins (`path_glob`) | non-core plugin libs | known third-party Unity plugin libs **not already in `trackers.toml`** | `Unity native plugin: <name>` |

### 2.3 Rule conventions

- `kind = "engine-detail"` on every rule, matching `scanners/unity.py` so all Unity
  facts share one report kind.
- `confidence`: `high` for an engine-specific lib/class path; `medium` for a shared
  resource-string heuristic (e.g. a bare `google_api_key`).
- `state`: default `present`; `referenced` for class-path (dex) hits where the symbol
  is referenced rather than merely bundled.
- **Dedup discipline:** the plugin/service rules must not re-detect SDKs already owned
  by `trackers.toml` (AppLovin, Vungle, AdColony, Firebase-Analytics-as-tracker, …).
  Unity bundle = Unity-*integration* markers (the `com.unity3d.services.*` surface,
  Firebase *config residue*, Addressables) that the tracker inventory does not assert.
  Overlap is resolved by keeping tracker SDKs out of this bundle, not by post-merge.

### 2.4 Example rules

```toml
[[rule]]
kind = "engine-detail"
subject = "Unity service: Analytics"
confidence = "high"
state = "referenced"
strings = ["com/unity3d/services/analytics"]
# content matcher: searches dex + .so + text under extracted/

[[rule]]
kind = "engine-detail"
subject = "Firebase config (google-services residue)"
confidence = "medium"
match = "any"
strings = ["google_app_id", "gcm_defaultSenderId", "firebase_database_url"]
targets = ["res/values/**", "**/strings.xml"]

[[rule]]
kind = "engine-detail"
subject = "Unity Addressables catalog"
confidence = "high"
match = "any"
globs = ["assets/aa/**/catalog*.json", "assets/aa/**/settings.json"]
```

---

## 3. Component B — Unity-gated bundle scanner

A one-liner scanner mirroring `scanners/engine.py`, consuming the new bundle:

```python
# scanners/unity_rules.py
def scan(ws: Workspace) -> list[Finding]:
    if not ws.extracted_dir.is_dir():
        return []
    return apply_bundle(load_builtin("unity"), ws.extracted_dir, load_manifest(ws))
```

Registered as a Unity-gated spec (see §5). Cache-keyed on the `unity` bundle version via
`ScannerSpec.bundles=("unity",)` — a bundle edit busts its cache automatically.

---

## 4. Component C — Addressables remote-URL scanner (code)

`scanners/unity_assets.py` — the one item that needs real code, because it parses
catalog JSON rather than matching a pattern.

**Contract:** `scan(ws) -> list[Finding]`. No-op unless `assets/aa/**/catalog*.json`
exists (Unity-gated *and* self-gated).

**Behaviour:**
- Locate catalog JSON under `assets/aa/`.
- Stream-parse bounded (catalogs can be large): pull the internal-id list
  (`m_InternalIds` / `InternalIdList`) and the resource-provider remote base entries.
- Emit a `Finding` per distinct **http(s) URL** found in the id list:
  `kind="engine-detail"`, `subject="Addressables remote content: <host>"`,
  `state="referenced"`, `Evidence.snippet=<url>`, `Location.file_path=<catalog rel>`,
  `tool="unity"`.

**Value vs. the endpoint scanner (important):** the Phase 6 `endpoint` scanner already
greps URLs out of JSON assets, so a raw Addressables URL is *already discovered*. This
scanner's job is **semantic attribution** — labelling those URLs as Addressables remote
content-delivery endpoints — not raw discovery. The emitted findings flow through the
existing `enrich_domain_attribution` post-pass like any other host.

---

## 5. Wiring the Unity gate

`run_all` currently does:

```python
if any(f.kind == "engine" and f.subject == "Unity" for f in findings):
    findings.extend(_run_spec(ws, UNITY_SPEC, meta))
```

Generalise the single `UNITY_SPEC` to a tuple and loop:

```python
UNITY_SPECS = (
    UNITY_SPEC,                                              # existing backend/metadata
    ScannerSpec("unity_rules", unity_rules.scan, ("unity",)),
    ScannerSpec("unity_assets", unity_assets.scan),         # code-only, keys on dumpa version
)
...
if any(f.kind == "engine" and f.subject == "Unity" for f in findings):
    for spec in UNITY_SPECS:
        findings.extend(_run_spec(ws, spec, meta))
```

No change to caching, enrichment, or report assembly — the new findings are ordinary
`engine-detail` Findings.

---

## 6. Component D — JADX decompilation (read-only)

JADX is registered in `core/tools.py` (`required=False`, version-probed). Wiring =
invocation + a command surface. Output is a **workspace artifact**, never a scanner
finding.

### 6.1 Command: `dumpa decompile`

```
dumpa decompile <input.apk|--workspace DIR> (--class a.b.C | --package a.b | --all)
                [--out DIR]
```

- **On-demand is enforced by requiring a selector.** With no `--class`/`--package`,
  the command errors and tells the user to pass one or `--all` (the explicit
  full-APK escape hatch — slow, GB-scale, opt-in).
- `--class a.b.C` → `jadx --single-class a.b.C -d <out>` (cheap, the primary path).
- `--package a.b` → JADX has no native package include; decompile to `<out>` then
  retain only `sources/<pkg path>/`. Heavier — documented as such. *(Impl detail to
  confirm in `/sc:workflow`: filter-after vs. per-class loop.)*
- `--out` defaults to `<workspace>/decompiled/`.
- **Tool absent:** `registry.resolve("jadx")` raises `ToolNotFoundError`; the command
  catches it, logs a warning, exits 0 (it is an optional capability, not a failure).

### 6.2 Flag: `analyze --jadx`

Convenience pass after the normal analysis. To honour on-demand it does **not**
decompile the whole APK — it defaults the selector to the app's **own package**
(manifest `package` attribute). Documented as the heavier-than-a-single-class path;
default off. JADX absent → step skipped with a warning, analysis still succeeds.

### 6.3 Reproducibility — and a correction to the brainstorm spec

The brainstorm note said JADX would be "the first versioned-external-tool invocation →
extends the scanner cache key to tool version." **That is wrong and is corrected here:**
decompile output is an *artifact*, not scanner findings, so it never touches the scanner
cache and the deferred tool-version-in-cache-key case does **not** land here (it still
waits for a versioned-tool *scanner*). Instead, provenance is recorded in a sidecar:

```
<out>/.dumpa-decompile.json  =  { tool: "jadx", version, selector, input_sha256 }
```

Presence of a matching sidecar lets a re-run skip; a different selector/input/version
re-runs. Simple, local to the artifact, no cache-layer change.

---

## 7. Data flow

```
analyze <input>
  └─ build_workspace (extract once)
  └─ run_all
       ├─ global SCANNERS …  (engine scanner emits engine/Unity)
       ├─ Unity gate fires ──► UNITY_SPECS:
       │      unity.py        → scripting backend, IL2CPP metadata   (existing)
       │      unity_rules     → services / Firebase / remote-config / Addressables presence / plugins  (rules/unity.toml)
       │      unity_assets    → Addressables remote URLs (semantic)  (code)
       └─ enrich_native_rvas / enrich_dex_locations / enrich_domain_attribution
  └─ build_report  (engine-detail findings render alongside the rest)
  └─ [--jadx]  ► decompile(app package) → <ws>/decompiled/  (artifact + sidecar)

dumpa decompile <input> --class … │ --package … │ --all
  └─ resolve jadx (absent → warn, exit 0)
  └─ jadx invocation → <out>/  + .dumpa-decompile.json
```

---

## 8. Interfaces / contracts summary

| Unit | Signature | Notes |
|------|-----------|-------|
| `scanners/unity_rules.py:scan` | `(ws) -> list[Finding]` | applies `unity` bundle; Unity-gated by registration |
| `scanners/unity_assets.py:scan` | `(ws) -> list[Finding]` | parses `assets/aa/**/catalog*.json`; self- + Unity-gated; bounded streaming |
| `commands/decompile.py:decompile` | `(input, *, workspace, selector, out) -> None` | jadx invoke; `ToolNotFoundError` → warn + return |
| `rules/unity.toml` | data | `kind="engine-detail"`; no tracker-SDK overlap |
| `run_all` change | — | `UNITY_SPEC` → `UNITY_SPECS` tuple, looped under the existing gate |

No changes to `core/report.py`, `core/cache.py`, or the export path.

---

## 9. Testing strategy (TDD targets for `/sc:workflow`)

- **Bundle loads:** `load_builtin("unity")` parses; `dumpa rules list` shows it.
- **Bundle matches:** synthetic `extracted/` trees — fake `assets/aa/catalog.json`,
  `res/values/strings.xml` with `google_app_id`, a dex blob containing
  `com/unity3d/services/analytics`, a `lib/arm64-v8a/libFirebaseCppApp.so` — assert the
  expected `engine-detail` subjects, confidence, and state.
- **No false positives:** a non-Unity tree yields zero `unity_rules`/`unity_assets`
  findings; verify the gate (no `engine/Unity` finding ⇒ specs never run).
- **No tracker overlap:** a tree with AppLovin (in `trackers.toml`) does not also
  surface a duplicate Unity-plugin finding.
- **Addressables URLs:** a catalog JSON with a remote `http(s)` id → one attributed
  finding per host; a catalog with only local ids → none.
- **decompile:** registry override pointing `jadx` at a stub script — assert the argv
  (`--single-class` for `--class`, output dir, sidecar written); override to a
  nonexistent path → warning + exit 0, no crash; no selector → usage error.
- Mirrors the existing ~104-test parser/matcher/scanner suite.

---

## 10. ROADMAP checkbox deltas (flip only on verified build)

- Phase 4 Unity helpers: plugin scanner, `Assets/Plugins/Android`, Unity services,
  Addressables, Firebase config, remote config → `[x]` (note the APK-merge reality for
  the plugins items).
- Phase 4 engine config-file parser `[~]` → addressed (Addressables/Firebase JSON +
  res-string parse).
- Phase 8 JADX `[~]` → `[x]` (read-only, on-demand; `dumpa decompile` + `analyze --jadx`).
- Phase 8 baksmali `[~]` → `[x]` *satisfied by apktool* (rewrite already operates on the
  apktool smali tree; no separate baksmali invocation).
```
