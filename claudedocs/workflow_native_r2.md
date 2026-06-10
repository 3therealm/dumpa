# Workflow — radare2 native region scanner

Implementation plan for the radare2-backed native region scanner (ROADMAP Phase 7).
TDD-oriented, dependency-ordered. **Plan only — no code in this doc.**

Closes: `[ ] radare2-backed region scanning`, `[~] suspicious regions → region map`,
`[~] scan-native --tool radare2`, and the deferred Architecture-Foundations line
*tool-version cache keying*.

## Locked decisions (from /sc:brainstorm + /sc:design)

1. radare2 CLI execution through the shared bounded process runner (no `r2pipe` dependency).
2. Sections/functions come from radare2 JSON; entropy is computed in Python over bounded file slices.
3. New `native-region` finding kind (no overload of `protection`).
4. Build bare `dumpa scan-native` **and** the `--tool radare2` deep path.
5. Primary/preferred ABI only.

## Strategy

- Bottom-up: cache key → ABI helper → r2 wrapper → scanner → pipeline wiring → command.
- Every code unit lands with its test first (mirror existing `tests/test_*.py`).
- External tool radare2 is **never** required: absence → warn + skip, fail-soft
  (jadx idiom, `commands/decompile.py:73`). Tests mock the process wrapper — no real binary in CI.

## Dependency graph

```
P1 cache key ──┐
P2 abi helper ─┤
P3 core/r2.py ─┴─► P4 scanners/native_r2.py ─► P5 pipeline wiring ─► P6 scan-native cmd ─► P7 analyze --r2
                                                                                            └─► P8 docs/roadmap
```
P1, P2, P3 are independent (parallelizable). P4 depends on P2+P3. P5 depends on P1+P4.
P6/P7 depend on P5. P8 last.

---

## Phase 1 — Cache key: fold in tool versions

**Why first:** the foundation line; `native_r2` is cacheable and its key must move when
radare2 upgrades, or the cache silently serves stale analysis.

- Test (`tests/test_cache.py`): extend — `compute_scanner_key` with a `tool_versions`
  dict produces a *different* key than without; key is stable under dict ordering;
  empty/None `tool_versions` reproduces the current key (back-compat, existing tests pass).
- Edit `core/cache.py`: add `tool_versions: dict[str,str] | None = None` param to
  `compute_scanner_key`; append sorted `f"tool:{n}:{v}"` parts after bundle parts.

**Verify:** `pytest tests/test_cache.py` green; existing key for bundle-only scanners
unchanged (golden-corpus cache hits still hit).

**Checkpoint C1:** key function back-compatible + tool-version-sensitive.

---

## Phase 2 — Primary-ABI helper

- Test (`tests/test_abi.py`, NEW): `select_primary_abi(["x86","arm64-v8a"]) == "arm64-v8a"`;
  preference order honored; unknown ABI falls through; empty → None.
- New `core/abi.py`: `_ARCH_PREFERENCE` (promoted from `tools/il2cpp/__init__.py:28`) +
  `select_primary_abi(abis: Iterable[str]) -> str | None`.
- Edit `tools/il2cpp/__init__.py`: import `_ARCH_PREFERENCE` from `core/abi.py` (single
  source; no behavior change — verify il2cpp tests still pass).

**Verify:** `pytest tests/test_abi.py tests/test_dump_il2cpp.py`.

**Checkpoint C2:** one ABI-preference source, shared.

---

## Phase 3 — core/r2.py CLI wrapper (fail-soft + timeout)

- Test (`tests/test_r2.py`, NEW), process runner mocked:
  - radare2 timeout / execution error → `analyze()` returns None (no raise).
  - happy path: fake stdout returns canned `iSj`/`aflj` JSON →
    `R2Analysis` with sections+functions+Python-computed per-section entropy.
  - malformed/truncated JSON → None, warning logged, no raise.
  - function inventory is capped while total count/truncation metadata is preserved.
- New `core/r2.py`:
  - `analyze(path, *, argv_prefix, timeout, max_bytes, max_functions, version) -> R2Analysis | None`:
    use the resolved radare2 argv prefix, guard `path.stat().st_size <= max_bytes`;
    run `aa`, collect `iSj` and `aflj`, and let `core.process.run` enforce timeout.
  - `R2Analysis` dataclass: `version`, `sections[]`, `functions[]`,
    `total_function_count`, `functions_truncated`.

**Verify:** `pytest tests/test_r2.py` green with **no radare2 installed** (process mocked).

**Checkpoint C3:** wrapper is fully fail-soft and CI-safe.

---

## Phase 4 — scanners/native_r2.py

Depends on P2 (abi) + P3 (r2).

- Test (`tests/test_native_r2.py`, NEW), r2 process mocked, synthetic `.so` via
  `tests/_elf_build.py`:
  - high-entropy `.text` section (canned entropy ≥7.2) → `native-region` finding,
    `classification="packed"`, `confidence=HIGH`, Location has `file_offset` **and** `rva`.
  - mid entropy (6.5–7.2) → `classification="high-entropy"`, MEDIUM.
  - low entropy → no region finding.
  - always emits one `native-function-summary` + writes
    `dumps/native-r2/<abi>__<lib>.json` sidecar (assert shape).
  - radare2 absent → `scan()` returns `[]`, warning logged (no raise).
  - only the **primary ABI** is analyzed when multiple ABIs present.
  - oversized `.so` (> max_bytes) → skipped with warning.
- New `scanners/native_r2.py`:
  - consts: `const_native_region_kind="native-region"`,
    `const_native_function_summary_kind="native-function-summary"`,
    `_ENTROPY_PACKED=7.2`, `_ENTROPY_ELEVATED=6.5`, `_MAX_BYTES`, `_TIMEOUT`.
  - `scan(ws) -> list[Finding]`: build registry from config (decompile.py pattern);
    pick `select_primary_abi`; for each `lib/<abi>/*.so` call `r2.analyze`; map sections→
    entropy regions; emit summary + bounded sidecar; FR3 disasm signals → `native-region`
    (`anti-debug`/`anti-disasm`/`self-modifying`).
  - Findings carry `Location(file_offset, rva=section vaddr)` so RVAs are correct without
    relying on the PT_LOAD pass.

**Verify:** `pytest tests/test_native_r2.py`.

**Checkpoint C4:** scanner produces correct findings + sidecar, fully mocked, fail-soft.

---

## Phase 5 — Pipeline wiring (opt-in spec + tool-version keying)

Depends on P1 + P4.

- Test (`tests/test_scanners.py`): extend —
  - `native_r2` is **not** in the default `run_all` output (opt-in).
  - `run_all(ws, extra=("native_r2",))` includes its findings.
  - `native_r2` is not cached, so transient tool absence/timeouts do not poison results.
- Edit `scanners/__init__.py`:
  - `ScannerSpec` gains `tools: tuple[str,...] = ()`.
  - `OPTIONAL_SPECS: dict[str, ScannerSpec]` with `native_r2`
    (`tools=("radare2",)`, `cacheable=False`).
  - `run_all(ws, *, use_cache=True, extra=(), registry=None)`: build one registry if None;
    append `OPTIONAL_SPECS[name]` for each `extra`; thread registry to `_run_spec`.
  - `_run_spec(...)`: resolve `spec.tools` versions (None-safe) → pass to
    `compute_scanner_key` as `tool_versions`.
  - `enrich_native_rvas` already no-ops when `rva` is set (`__init__.py:125`) — confirm no
    double-set conflict with r2 vaddr.

**Verify:** `pytest tests/test_scanners.py tests/test_cache.py`.

**Checkpoint C5:** opt-in scanner runs only on request; default scanner caches stay intact;
default pipeline byte-identical (golden corpus unaffected).

---

## Phase 6 — `dumpa scan-native` command

Depends on P5.

- Test (`tests/test_scan_native_cmd.py`, NEW):
  - bare `scan-native <apk>` over a populated workspace → runs `native` scan, prints a
    table, exit 0.
  - `--tool radare2` → also runs `native_r2` (mocked) findings appear.
  - radare2 absent + `--tool radare2` → warns, still exits 0 with ELF-only results.
  - workspace populate path reuses `decompile.py` helpers.
- New `commands/scan_native.py`: mirror `decompile.py` structure (config → registry →
  workspace resolve/populate). `--tool radare2` flag selects the deep path
  (`run_all(..., extra=("native_r2",))` or direct `native_r2.scan`).
- Edit `cli.py`: register `scan-native`.

**Verify:** `pytest tests/test_scan_native_cmd.py`; manual `dumpa scan-native --help`.

**Checkpoint C6:** dedicated command closes the UX gap; deep path opt-in.

---

## Phase 7 — `analyze --r2`

Depends on P5.

- Test (`tests/test_scanners.py` or analyze test): `analyze(..., r2=True)` persists
  `optional_scanners=("native_r2",)` in workspace metadata; default `analyze` unchanged.
- Edit `commands/analyze.py`: add `--r2` flag → persist the optional scanner and let
  `build_report` derive extras from metadata on future rebuilds.

**Verify:** `pytest`; `dumpa analyze <apk> --r2 --workspace out/` (manual, if radare2 present).

**Checkpoint C7:** inline opt-in path wired.

---

## Phase 8 — Docs + roadmap

- Update `ROADMAP.md` Phase 7: flip `radare2-backed region scanning` → `[x]`,
  `suspicious regions` → `[x]` (region map), `scan-native --tool radare2` → `[x]`;
  note tool-version cache keying now lands in `core/cache.py`.
- Brief module docstrings (native_r2.py, core/r2.py) per house style.

**Checkpoint C8:** roadmap reflects reality.

---

## Quality gates (run before "done")

- `pytest` — full suite green, **no radare2 binary required** (everything mocked).
- Golden corpus (`tests/test_golden_corpus.py`) — default report projection unchanged
  (native_r2 is opt-in, must not perturb it).
- `dumpa doctor` — radare2 still probed (already registered).
- Lint/format per repo config.
- Manual smoke (if radare2 installed): `dumpa scan-native <apk> --tool radare2` on a real
  Unity game; confirm `libil2cpp.so` entropy region + function summary + sidecar.

## Risk register

| Risk | Mitigation |
|------|-----------|
| `aaa` too slow on 195MB `libil2cpp.so` | depth = `aa`+`aflj`; per-lib timeout + max_bytes; primary ABI only |
| radare2 process hangs | shared process runner enforces timeout and kills child |
| Python dependency breaks zero-dep installs | no `r2pipe`; external tool absence → warn+skip; CI mocks process runner |
| stale empty cache after transient r2 failure | native_r2 is non-cacheable |
| double RVA set (PT_LOAD vs r2 vaddr) | enrich pass skips when rva already set |

## Out of scope (v1)

Decompilation pipeline (r2dec/ghidra), non-primary ABIs, persisted report from bare
`scan-native` (analyze owns reports), IPv6/SARIF (unrelated roadmap lines).
