# Workflow — Phase 4 Cocos2d-x + Godot Deep Helpers

> Implementation plan only. No code in this document. Execute with `/sc:implement` PR by PR.
> Derived from the `/sc:brainstorm` → `/sc:design` chain. Closes the last two open Phase 4 items.

## Locked decisions (carried from brainstorm + design)

- **Sequence:** PR 1 Cocos2d-x, then PR 2 Godot.
- **Decrypt/extract posture:** auto-decrypt / auto-extract when a key/unencrypted-pack is found (policy-gated to owned apps; key *material* never enters the report).
- **Version scope v1:** Godot 3.x + mainline Cocos XXTEA. Defer Godot-4 encrypted PCK, `.gdc`→source decompile, non-XXTEA Cocos ciphers.
- **Output:** Findings + artifacts under `dumps/<engine>/` with a `.dumpa-<engine>.json` provenance sidecar.
- **Deps:** none. Zero-dep stdlib parsers (`core/elf.py` / `core/axml.py` ethos). No new doctor probe.

## Conventions this plan binds to (from the codebase)

- Deep helper = pure `scan(ws) -> list[Finding]`; internal no-op guard; engine-gated in `run_all` (`scanners/__init__.py:322`, the `UNITY_SPECS` pattern).
- Findings carry `kind="engine-detail"`, `subject`, `confidence`, `state`, `evidence` (snippet+tool), `locations`.
- Artifacts under `ws.dumps_dir / "<engine>"`; scanners writing `dumps/` sidecars is already blessed (`native_dir`, `dex_dir`).
- Provenance sidecar = `.dumpa-<engine>.json`, `json.dumps(..., indent=2, sort_keys=True)` (decompile pattern).
- Tests: flat `tests/`, fixture builders named `_<thing>_build.py` (cf. `_axml_build.py`, `_elf_build.py`, `_dex_build.py`).

---

## PR 1 — Cocos2d-x

### Dependency graph
```
T1 core/xxtea.py ──┐
                   ├─► T3 scanners/cocos.py ──► T4 register+gate ──► T5 ROADMAP+verify
T2 _xxtea_build ───┘                       ▲
                   T2b cocos fixture ───────┘
```
T1 and T2/T2b are independent (parallelizable). T3 needs T1. T4 needs T3. T5 last.

### T1 — `core/xxtea.py` (TDD)
- **Write test first** (`tests/test_xxtea.py`): reference-encrypt a known plaintext (inline reference XXTEA encrypt in the test), assert `decrypt` round-trips; assert `decrypt_signed` returns `None` on sign mismatch and strips the sign on match.
- **Implement:** `decrypt(data, key) -> bytes` (big-endian words, delta `0x9E3779B9`, `6 + 52//n` rounds); `decrypt_signed(blob, key, sign) -> bytes | None`; `const_default_sign = b"XXTEA"`.
- **Verify:** `pytest tests/test_xxtea.py` green. Pure, no I/O.
- **Checkpoint C1:** XXTEA primitive proven by round-trip.

### T2 — `tests/_xxtea_build.py` + cocos fixture (parallel with T1)
- Builder: produce a signed-encrypted `.jsc`/`.luac` blob from plaintext + key + sign (uses a reference encrypt; the decrypt side under test must recover it).
- Fixture: a minimal extracted-tree builder — `lib/<abi>/libcocos2djs.so` carrying the key+sign string near a `setXXTEAKeyAndSign` marker, plus `assets/script.jsc` encrypted with that key.
- **Checkpoint C2:** fixture builds an extracted workspace dir on disk.

### T3 — `scanners/cocos.py` (TDD, needs T1+T2)
- **Write tests** (`tests/test_cocos.py`):
  1. key-in-`.so` fixture → bundles located, key recovered, `dumps/cocos/decrypted/*` written, decrypt-count finding present, sidecar valid JSON.
  2. no-key fixture (strip the key string) → bundles reported `encrypted`, **no** writes, no crash.
  3. non-cocos extracted dir → `scan` returns `[]`.
  4. report never contains key *material*, only `key_source`.
- **Implement** per design §3.2: `_version`, `_locate_bundles`, `_bundle_findings`, `_discover_key` (harvest candidate strings near `setXXTEAKeyAndSign`, confirm by trial-decrypt magic check), `_decrypt_all` (writes artifacts + sidecar), `_encrypted_findings`.
- **Verify:** `pytest tests/test_cocos.py` green.
- **Checkpoint C3:** scanner passes all four cases; key material absent from findings.

### T4 — register + gate (`scanners/__init__.py`)
- Add `COCOS_SPECS = (ScannerSpec("cocos", cocos.scan),)`; import `cocos`.
- In `run_all`, after engine findings: gate on `subject=="Cocos2d-x"` (mirror line 322 Unity gate).
- **Verify:** add/extend an integration test asserting cocos findings appear in a full `run_all` over the fixture, and are absent for a non-cocos input.
- **Checkpoint C4:** cocos helper fires only when detection fired.

### T5 — docs + full verify
- Flip `ROADMAP.md` line 162 Cocos2d-x `[~]`→`[x]`; expand line 305–312 sub-bullets; keep deferred (non-XXTEA ciphers) explicit.
- **Verify:** full `pytest`; `dumpa analyze` smoke on the fixture if a real cocos sample is available.
- **Checkpoint C5 (PR1 done):** all tests green, ROADMAP updated, no new deps, key material never reported.

### PR 1 quality gates
- [ ] XXTEA round-trip + sign-mismatch tested
- [ ] decrypt / no-key / non-cocos / no-key-leak cases tested
- [ ] artifacts + provenance sidecar written deterministically
- [ ] engine-gated; zero cost on non-cocos apps
- [ ] zero new external deps; ROADMAP flipped

---

## PR 2 — Godot

### Dependency graph
```
T6 core/pck.py ───┐
                  ├─► T8 scanners/godot.py ──► T9 register+gate ──► T10 ROADMAP+verify
T7 _pck_build ────┘                        ▲
                  T7b godot fixture ────────┘
```

### T6 — `core/pck.py` (TDD, Godot 3.x `GDPC`)
- **Write tests** (`tests/test_pck.py`): hand-built minimal 2-entry GDPC blob → `parse_standalone` returns correct `godot_version` + entries; `extract` writes both files with correct bytes; `find_embedded` locates a footer-appended pack in a synthetic `.so`; encrypted-flag header → `is_encrypted` true.
- **Implement** per design §4.1: dataclasses `PckEntry`/`Pck`; `parse_standalone`, `find_embedded`, `parse_at`, `extract`, `is_encrypted`. Bounds-check path_len/file_count against file size (no over-read).
- **Checkpoint C6:** PCK parse + extract + embedded-locate proven.

### T7 — `tests/_pck_build.py` + godot fixture (parallel with T6)
- Builder: emit a valid Godot-3.x GDPC blob from a dict of `{path: bytes}`; variant that appends the blob to a stub `.so` with the trailing footer (embedded case); variant with the encrypted flag set.
- Fixture: extracted tree with `lib/<abi>/libgodot_android.so` (embedded pack) and/or a standalone `assets/game.pck`, plus a `project.godot` and a `.gdc` file.
- **Checkpoint C7:** fixtures build standalone, embedded, and encrypted variants.

### T8 — `scanners/godot.py` (TDD, needs T6+T7)
- **Write tests** (`tests/test_godot.py`):
  1. standalone pck fixture → version detected, files listed, `dumps/godot/pck/*` extracted, sidecar valid.
  2. embedded pck fixture → located at offset, extracted.
  3. encrypted-flag pck → reported `encrypted` finding, **no** extract, no crash.
  4. `project.godot` + `.gdc` present → config + bytecode findings.
  5. non-godot dir → `[]`.
- **Implement** per design §4.2: collect standalone + embedded packs, `_version`, `_listing`, auto-`extract`, `_extracted`, `_encrypted` (skip), `_config_scan`.
- **Checkpoint C8:** all five cases green.

### T9 — register + gate
- Add `GODOT_SPECS = (ScannerSpec("godot", godot.scan),)`; gate on `subject=="Godot"` in `run_all`.
- **Verify:** integration test — godot findings present in full `run_all` over the fixture, absent otherwise.
- **Checkpoint C9:** godot helper engine-gated.

### T10 — docs + full verify
- Flip `ROADMAP.md` line 162 Godot `[~]`→`[x]`; expand line 313–317 sub-bullets; keep Godot-4 encrypted PCK + `.gdc`→source **explicitly deferred**.
- **Verify:** full `pytest`; `dumpa analyze` smoke if a real godot sample exists.
- **Checkpoint C10 (PR2 done + Phase 4 closed):** all tests green; both engine lines `[x]`; deferred items documented.

### PR 2 quality gates
- [ ] PCK parse / extract / embedded-locate / encrypted-flag tested
- [ ] standalone + embedded + encrypted + config + non-godot cases tested
- [ ] bounds-checked parsing (no over-read on hostile headers)
- [ ] engine-gated; zero cost on non-godot apps
- [ ] zero new external deps; ROADMAP flipped; Phase 4 fully `[x]` except documented defers

---

## Execution order summary

| Step | File | Type | Depends on | Checkpoint |
|------|------|------|-----------|-----------|
| T1 | `core/xxtea.py` | core (TDD) | — | C1 |
| T2 | `tests/_xxtea_build.py` + fixture | test infra | — | C2 |
| T3 | `scanners/cocos.py` | scanner (TDD) | T1,T2 | C3 |
| T4 | `scanners/__init__.py` gate | wiring | T3 | C4 |
| T5 | ROADMAP + full verify | docs | T4 | C5 (PR1) |
| T6 | `core/pck.py` | core (TDD) | — | C6 |
| T7 | `tests/_pck_build.py` + fixture | test infra | — | C7 |
| T8 | `scanners/godot.py` | scanner (TDD) | T6,T7 | C8 |
| T9 | `scanners/__init__.py` gate | wiring | T8 | C9 |
| T10 | ROADMAP + full verify | docs | T9 | C10 (PR2, Phase 4 closed) |

## Cross-cutting validation (both PRs)
- Memory: key-search via bounded-chunk content reader; PCK table small; extraction streams per entry.
- Reproducibility: provenance carries `dumpa_version` + detected engine version; artifacts deterministic.
- Security/policy: auto-decrypt/extract justified by the roadmap "inspect assets of an app you own" clause; report logs key **source**, never key bytes.
- No-op: both scanners return `[]` before glob cost on the wrong engine (belt-and-suspenders behind the `run_all` gate).

## Risks / open implementation notes
- **Cocos key discovery is heuristic.** Trial-decrypt magic check is the confirmation gate; if no candidate confirms, fall back to `encrypted` reporting (no guess written). Acceptable for v1.
- **Cocos custom sign.** Some apps set a non-default sign; `_discover_key` must harvest the sign alongside the key, not assume `"XXTEA"`.
- **Godot Android pack location varies by export.** Cover both standalone `assets/*.pck` and `.so`-embedded; if a real sample reveals a third layout, note and defer.
- **Godot 4 PCK** (different format version + optional encryption) → detected via `pack_format_version` / enc flag and reported-then-skipped, not parsed.
