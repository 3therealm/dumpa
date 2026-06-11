# Workflow — Unity Asset Parser

Implementation plan for `docs/unity-asset-parser-design.md`. Closes ROADMAP.md Phase 6
`[~]` Unity-asset endpoint gap (line 514). TDD-first, surgical, conforming to the
Godot/Cocos deep-helper template.

**Strategy:** systematic · **Depth:** normal · **Persona lead:** backend/python-expert
**Next step after this doc:** `/sc:implement` phase by phase.

---

## Dependency graph

```
P0 dep+scaffold ─► P1 adapter (core/unityasset.py) ─► P2 scanner extend ─► P3 registry+wire ─► P4 doctor ─► P5 docs/roadmap
                         │                                  │
                    (mock target)                    P2 tests mock P1
```

Critical path: **P0 → P1 → P2 → P3**. P4 (doctor) and P5 (docs) are leaf, parallelizable
after P3. Each phase ends green (`pytest`) before the next starts.

---

## Phase 0 — Dependency + scaffold

**Goal:** UnityPy installable as an optional extra; empty adapter importable.

- T0.1 `pyproject.toml`: add `[project.optional-dependencies] unity = ["UnityPy>=1.20"]`.
- T0.2 Install into the dev env: `uv pip install -e '.[unity]'` (or the project's venv path).
- T0.3 Create `src/dumpa/core/unityasset.py` skeleton: module docstring + `UnityPyUnavailable`,
  `available()`, `unitypy_version()` only (no parse yet). **No top-level `import UnityPy`** —
  import lazily inside functions so the module imports clean without the extra.

**Verify (checkpoint C0):**
- `python -c "import dumpa.core.unityasset"` succeeds with AND without UnityPy installed.
- `available()` returns True in the dev env (extra installed), and is the *only* gate the
  rest of the code consults.

---

## Phase 1 — Adapter (`core/unityasset.py`)

**Goal:** turn a container path into `list[ExtractedString]` + raw TextAsset bytes, bounded
and fail-soft. This is the one file that touches UnityPy.

- T1.1 Dataclasses `ExtractedString`, `DumpedAsset` (fields per design).
- T1.2 `parse_container(path, *, max_obj, max_bytes_per_obj)`:
  - lazy `import UnityPy`; `UnityPy.load(str(path))`.
  - iterate `env.objects`; per-object `try/except` → log+skip (UnityPy throws on exotic versions).
  - `TextAsset` → `obj.read()`; pull `m_Name` + `m_Script` (str|bytes); truncate at
    `max_bytes_per_obj`; yield `ExtractedString` + raw bytes.
  - `MonoBehaviour` → `obj.read_typetree()`; walk dict/list leaves, collect `str` values
    (bounded count + length); yield `ExtractedString` (no raw bytes).
  - stop after `max_obj` objects.
- T1.3 `unitypy_version()` via `importlib.metadata.version("UnityPy")`, None on absence.

**Tests — `tests/test_unityasset.py`** (skip-if-absent, golden-corpus pattern):
```python
unitypy = pytest.importorskip("UnityPy")   # skip whole module if extra not installed
```
- T1.4 Commit a *tiny* real fixture (`tests/fixtures/unity/sample.assets`) containing one
  TextAsset whose body is `https://api.example.com/v1 AIzaSyTESTKEY...`. Generate it **once**
  via UnityPy's save path in a `_unity_build.py` helper (mirrors `_pck_build.py`/`_elf_build.py`);
  commit the bytes so CI without UnityPy still has the file (the test skips, not the asset).
- T1.5 `test_parse_container_extracts_textasset`: ExtractedString carries the URL, asset_name,
  path_id, class_name="TextAsset".
- T1.6 `test_parse_container_bounds`: `max_obj=0` → empty; oversized `max_bytes_per_obj` truncates.
- T1.7 `test_parse_container_failsoft`: a garbage/non-Unity file → `[]` + logged warning, no raise.

**Verify (C1):** `pytest tests/test_unityasset.py` green (or skipped cleanly without UnityPy).

---

## Phase 2 — Scanner extension (`scanners/unity_assets.py`)

**Goal:** wire the adapter into the scanner: locate → parse → dump → harvest endpoints +
secrets → sidecar → summary. **Keep the existing `_addressables` path byte-for-byte.**

- T2.1 `_locate(extracted_dir)`: container globs (design §location), `is_relative_to(root)`
  guard, dedup — mirror `_catalogs()`.
- T2.2 `_dump_textassets(ws, container, raw_texts, strings)`: write to
  `dumps/unity/assets/<sanitized>__<path_id>`; enforce `_MAX_DUMP_FILES`/`_MAX_DUMP_TOTAL`,
  `log()` when capped; return `list[DumpedAsset]`.
- T2.3 `_endpoint_findings(strings, dumped, ws)`: run `endpoint.harvest_urls` over each
  string's text + each dumped file's bytes; emit `kind="endpoint"` findings with
  dump-relative `Location` + `asset_name`/`path_id` attributes. Copy godot's `_endpoint_findings`
  shape (host dedup, `_MAX_HOSTS`).
- T2.4 `_secret_findings(ws)`: `apply_bundle(load_builtin("secrets"), ws.dumps_dir/"unity/assets")`
  guarded on the dir existing.
- T2.5 `_summary_finding` (`engine-detail`: container/textasset counts) + `_write_sidecar`
  (`dumps/unity/.dumpa-unity-assets.json`, includes `unitypy_version`).
- T2.6 Rework `scan(ws)` per design control-flow; early-return Addressables-only when
  `not unityasset.available()` (warn) or no containers (silent no-op).
- T2.7 Update the module docstring: it is no longer Addressables-only.

**Tests — extend `tests/test_unity_scanners.py`** (mock the adapter — no UnityPy needed):
- T2.8 `test_unity_assets_skips_without_unitypy`: monkeypatch `unityasset.available -> False`;
  scan still returns Addressables findings, no crash.
- T2.9 `test_unity_assets_endpoint_from_textasset`: monkeypatch `unityasset.parse_container`
  to return a canned ExtractedString with a URL; assert an `endpoint` finding for the host
  with a `dumps/unity/assets/...` location.
- T2.10 `test_unity_assets_secret_from_dump`: dump dir seeded with an `AIza...` TextAsset →
  `secret` finding.
- T2.11 `test_unity_assets_dump_cap`: exceed `_MAX_DUMP_FILES` → capped + warning logged.
- T2.12 `test_unity_assets_sidecar_written`: sidecar exists with `unitypy_version` key.

**Verify (C2):** `pytest tests/test_unity_scanners.py` green; Addressables tests unchanged.

---

## Phase 3 — Registry + end-to-end wiring

**Goal:** the scanner runs under the Unity gate, uncached, and flows through the shared tail.

- T3.1 `scanners/__init__.py`: `unity_assets` spec → `cacheable=False`; update the comment
  above `UNITY_SPECS` (it currently says unity_assets is "code-only / keyed on dumpa version").
- T3.2 Confirm no `run_all` change needed (Unity gate already iterates `UNITY_SPECS`).

**Tests:**
- T3.3 `test_unity_assets_runs_under_gate` (extend `test_unity_scanners.py`): a workspace with
  a Unity engine marker + mocked adapter → `run_all` includes the endpoint finding, and the
  shared `enrich_domain_attribution`/`_purpose` tail tags it (assert purpose/owner where applicable).
- T3.4 `test_unity_assets_uncached`: two `run_all` passes reproduce dumps (no stale-cache skip).

**Verify (C3):** `pytest tests/` fully green. Manual smoke (optional, if a real Unity apk is in
the gitignored corpus): `dumpa analyze <unity.apk> --workspace /tmp/ws` → endpoints/secrets from
`dumps/unity/assets/` appear in the report.

---

## Phase 4 — Doctor surfacing (OQ4, low effort)

- T4.1 `commands/doctor.py --full`: advisory line reporting UnityPy import presence
  (`unityasset.available()`), mirroring the signature-DB advisory checks. Does **not** affect
  exit code.
- T4.2 Extend `tests/test_doctor.py`: `--full` output mentions UnityPy state.

**Verify (C4):** `dumpa doctor --full` shows the UnityPy line; test green.

---

## Phase 5 — Docs + roadmap

- T5.1 ROADMAP.md line 514: flip `[~] Unity assets` → `[x]` with a one-line note (parser via
  `core/unityasset.py` (UnityPy) + `scanners/unity_assets.py`; TextAssets dumped to
  `dumps/unity/assets/`, endpoints + secrets harvested). Also update the Phase 6 parent
  `[~] endpoint extraction` if Unreal is the only remaining `[~]` child (it is — keep parent `[~]`).
- T5.2 README/optional-deps note: `pip install dumpa[unity]` for Unity asset parsing.
- T5.3 Project memory: record Unity-asset-parser shipped + UnityPy optional-dep decision.

**Verify (C5):** roadmap reflects reality; `git diff` shows only intended lines.

---

## Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| UnityPy API drift across versions | All UnityPy calls isolated in `core/unityasset.py`; pin `>=1.20`; per-object try/except |
| Fixture generation needs UnityPy in CI | Commit generated bytes; tests `importorskip` — CI without the extra skips, never fails |
| UnityPy loads containers whole (no stream) | `_MAX_TOTAL_BYTES` + per-container size check skip giant `.assets` before load |
| Encrypted/custom bundles unreadable | Defer (warn), per design OQ1 — Godot-4 precedent |
| `dumps/` explosion | `_MAX_DUMP_FILES`/`_MAX_DUMP_TOTAL` with logged truncation |

## Definition of done

- [ ] `pytest tests/` green with and without the `unity` extra (skip, not fail, when absent)
- [ ] `analyze` on a Unity app surfaces TextAsset-derived endpoints + secrets with
      `dumps/unity/assets/` locations
- [ ] Addressables behaviour unchanged (existing tests pass untouched)
- [ ] `dumpa doctor --full` reports UnityPy presence
- [ ] ROADMAP.md Phase 6 Unity-asset item marked `[x]`
- [ ] `git diff` is surgical — no unrelated edits

## Estimated scope

~5 source files (1 new, 4 edited), ~2 test files (1 new, 1 extended), 1 fixture builder +
committed binary fixture. Adapter + scanner are the bulk; registry/doctor/docs are small.
