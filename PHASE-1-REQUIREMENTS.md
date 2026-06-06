# Phase 1 Requirements — APK/XAPK Foundation

Requirements specification for ROADMAP.md Phase 1. Produced by `/sc:brainstorm`.
**Scope: requirements only.** Architecture, layout schemas, and CLI contracts are
decided in `/sc:design`; implementation order in `/sc:workflow` or `/deep-plan`.

## Locked Decisions

| Fork | Decision |
|------|----------|
| Workspace foundation depth | **Workspace dir only.** Persistent reproducible directory + layout. Content-hash caching deferred to when `diff`/`load` need it (Phase 10). |
| Existing commands vs workspace | **`analyze` is umbrella.** It extracts once into the workspace; `convert` and `dump-il2cpp` read that workspace. Existing commands refactor onto a shared workspace primitive. |
| `dumpa info` depth | **Facts only.** aapt/manifest/zip facts. No engine detection (stays Phase 4). |
| Priority | **Workspace first.** `info` and signing presets ride on top. |

Implication: build the workspace **primitive** now, without the caching **layer**.

## Goals

- A user can point one command at an APK or XAPK and get a single, persistent,
  reproducible workspace directory — no manual unpacking, no re-extracting a
  195 MB apk per command.
- `convert` and `dump-il2cpp` stop owning private ephemeral tmp dirs and instead
  operate over the shared workspace.
- A user can get fast triage facts (`info`) without a full analysis.
- Signing is selectable by preset and is exercised end-to-end with a real keystore.

## Current State (baseline)

- `convert` and `dump-il2cpp` each create their own ephemeral `working_tmp_dir`
  (`core/fs.py`), extract independently, and wipe on exit. Nothing is cached or
  shared.
- `convert` writes the merged `.apk` to the current working directory.
- Signing: config + verification code exists (parses v1/v2/v3); **not yet
  exercised end-to-end with a real keystore.**
- Adapters present: apktool, zipalign, apksigner, aapt. il2cpp engines present.

## Functional Requirements

### FR1 — Workspace primitive (`core/workspace.py`)

- A persistent, reproducible directory that survives the run (unlike
  `working_tmp_dir`).
- Defined, documented top-level layout for: extracted app contents, dumps
  (il2cpp output), and a place for future reports. (Exact tree → design.)
- Records the input file's SHA-256 so findings are tied to one exact artifact
  (a Success Criterion in ROADMAP). Minimal — not the full Phase 2 report.
- Avoids double-storing large files (reuse existing `link_or_copy` hardlink path).
- Defined reuse semantics when the target workspace already exists
  (reuse vs rebuild vs error). (→ open question O5.)

### FR2 — `dumpa analyze <app.apk|app.xapk> --workspace out/`

- Accepts both `.apk` and `.xapk` inputs.
- `.xapk` → runs the existing merge pipeline, landing the merged app in the
  workspace.
- `.apk` → extracts into the workspace.
- Extracts **once**; later operations in the same run (and re-runs against the
  same workspace) reuse the extracted contents.

### FR3 — Refactor `convert` + `dump-il2cpp` onto the workspace

- Both operate over the shared workspace primitive instead of a private tmp dir.
- `dump-il2cpp` reads `lib/<abi>/libil2cpp.so` + `global-metadata.dat` from the
  already-extracted workspace rather than re-extracting the apk.
- `convert` lands its merged apk in the workspace.
- Existing CLI behavior of `convert` / `dump-il2cpp` keeps working
  (back-compat). Whether standalone invocations stay ephemeral-by-default or
  always create a workspace → open question O3.

### FR4 — `dumpa info <app.apk|app.xapk>`

- Fast triage, **no deep analysis / no apktool decode**.
- Reports: package name, versionName, versionCode, min/target SDK, ABIs
  (from `lib/<abi>/`), file size, signer certificate SHA-256, signing schemes
  (v1/v2/v3), permission count.
- Sources: aapt badging + apksigner cert + zip listing.
- On `.xapk`, reads the base/main split. (→ open question O7.)

### FR5 — Signing presets

- Selectable presets:
  - **unsigned** (current default)
  - **debug** (debug-keystore signing)
  - **custom keystore** (current config-driven path)
- Reproducible signing metadata surfaced in output: signer cert SHA-256, schemes,
  keystore source.
- Close the gap: exercise the signing path end-to-end with a real keystore.
- Debug keystore: auto-generate vs require user-provided → open question O6.
- CLI surface (`--signing <preset>` vs flags) → design.

## Non-Functional Requirements

- **Reproducibility**: input hash + tool versions recoverable from the workspace.
- **No new dependencies**: stdlib + existing external tools only.
- **Disk**: a persistent workspace raises peak disk vs the wipe-on-exit model;
  must be documented, and large files hardlinked not copied where possible.
- **Back-compat**: existing `convert` / `dump-il2cpp` / `doctor` CLIs unchanged.
- **No regressions** in the verified 195 MB Unity convert + dump path.

## User Stories / Acceptance Criteria

- **US1**: As an analyst, `dumpa analyze game.xapk --workspace out/` produces a
  reusable workspace; running `dump-il2cpp` against it does **not** re-extract.
  *Accept:* second op logs reuse / shows no second extraction; one extraction on disk.
- **US2**: `dumpa info game.apk` prints package, version, ABIs, size, signer
  SHA-256, schemes, and permission count in seconds with no apktool decode.
  *Accept:* completes without invoking apktool; fields populated on a real apk.
- **US3**: `dumpa convert game.xapk --signing debug` yields a debug-signed,
  installable apk, and the output reports cert SHA-256 + schemes.
  *Accept:* `apksigner verify` passes; reported cert matches the keystore.
- **US4**: Re-running `analyze` against an existing workspace behaves per the
  agreed reuse semantics (O5) — no silent corruption, no surprise wipe.
- **US5**: A reproducibility check can read the input SHA-256 back from the
  workspace.

## Open Questions (resolve in `/sc:design`)

- **O1 — Canonical extracted form.** `dump-il2cpp` needs raw zip contents
  (`lib/...so`, `global-metadata.dat`); `convert` produces an apktool-decoded
  tree. Does the workspace store the decoded tree, the raw zip extract, the
  merged apk, or a combination? This is the central design decision.
- **O2 — Default workspace path** when `--workspace` is omitted from `analyze`:
  required arg, or default to `./<stem>-workspace/`?
- **O3 — Standalone `convert`/`dump-il2cpp`**: stay ephemeral-by-default with
  opt-in `--workspace`, or always create a workspace?
- **O4 — Workspace metadata marker**: is the minimal input-hash record (FR1) a
  plain marker file now, or fully deferred with Phase 2's report? (Tension:
  reproducibility Success Criterion vs the "dir only" decision.)
- **O5 — Reuse semantics**: existing workspace → reuse / `--force` rebuild / error?
- **O6 — Debug keystore**: auto-generate (à la `~/.android/debug.keystore`) or
  require user-provided?
- **O7 — `info` on XAPK**: confirm "base/main split" is the right source for
  cert + manifest facts.

## Out of Scope for Phase 1

- Content-hash caching (Phase 10 driver: `diff`/`load`).
- Engine detection (Phase 4) — including any engine sniff in `info`.
- The unified finding model / report exporters (Phase 2).
- Streaming scanners (no large-file scanners exist yet).

## Next Step

`/sc:design` to resolve O1–O7 and define the workspace layout, the
`analyze`/`convert`/`dump-il2cpp` command contracts, and the signing-preset CLI.
