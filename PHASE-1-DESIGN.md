# Phase 1 Design — APK/XAPK Foundation

Design specification for ROADMAP.md Phase 1. Produced by `/sc:design`, building on
`PHASE-1-REQUIREMENTS.md`. **Design only** — interfaces, contracts, data flow.
Implementation in `/sc:implement` or `/deep-plan`.

## Open Questions — Resolutions

| # | Question | Resolution |
|---|----------|-----------|
| **O1** | Canonical extracted form | **Raw zip extract of the single (merged) apk is canonical `extracted/`.** The apktool-decoded tree is convert-internal scratch, dropped after the merged apk is built. Rationale: il2cpp/info/native/asset scanners all want raw zip contents; only convert needs the decoded tree, and it produces a merged apk that is then zip-extracted. |
| **O2** | Default workspace path | **Optional `--workspace`; default `./<stem>-workspace/`.** Mirrors the existing `dump-il2cpp` `<stem>-il2cpp` default. |
| **O3** | Standalone convert/dump-il2cpp | **One primitive, two lifetimes.** `--workspace` → persistent. Omitted → ephemeral workspace (temp dir, wiped on exit, `DUMPA_KEEP_TMP` honored) = today's behavior. No CLI breakage. |
| **O4** | Workspace metadata marker | **Minimal `workspace.json` now.** Holds schema_version, dumpa version, input path/sha256/size/type, created timestamp, tool versions. A marker for reproducibility — NOT the Phase 2 report. |
| **O5** | Reuse semantics | **Reuse when `workspace.json` present and input sha256 matches.** Mismatch → error unless `--force`. Non-empty dir without `workspace.json` → refuse (don't clobber). Empty/absent → create. `--force` wipes and rebuilds. |
| **O6** | Debug keystore | **Auto-managed.** Reuse `~/.android/debug.keystore` if present; else generate a dumpa-managed debug keystore (alias `androiddebugkey`, store/key pass `android`, `CN=Android Debug,O=Android,C=US`) under `$XDG_DATA_HOME/dumpa/`. No user input. |
| **O7** | `info` on XAPK | **Base/main split** for cert + manifest facts; ABIs from the xapk manifest's split list (or `native-code:` of the merged/base apk). Confirmed. |

## Workspace Layout

```
<stem>-workspace/
├── workspace.json        # FR1 marker (schema below)
├── app.apk               # canonical single apk
│                         #   xapk input -> merged output; apk input -> hardlink/copy of input
├── extracted/            # O1 canonical form: raw zip extract of app.apk
│   ├── AndroidManifest.xml   (binary)
│   ├── classes*.dex
│   ├── resources.arsc
│   ├── lib/<abi>/*.so        (incl. libil2cpp.so)
│   └── assets/...            (incl. global-metadata.dat)
├── dumps/                # il2cpp output: dump.cs, il2cpp.h, script.json, ...
└── reports/              # reserved for Phase 2 (created lazily/empty)
```

Convert scratch (apktool decode + merge tree) lives in a transient dir **outside**
this layout (or under a `.scratch/` that is removed once `app.apk` is built),
honoring O1 + the no-double-store NFR. `DUMPA_KEEP_TMP=1` retains it.

### `workspace.json` schema

```json
{
  "schema_version": 1,
  "dumpa_version": "0.x.y",
  "input": { "path": "/abs/game.xapk", "sha256": "<hex>", "size": 204472320, "type": "xapk" },
  "created": "2026-06-06T00:00:00Z",
  "tool_versions": { "apktool": "2.9.3", "apksigner": "...", "aapt": "..." }
}
```

`type` ∈ {`apk`, `xapk`}. `tool_versions` records only tools actually invoked.

## Component Design

### `core/hashing.py` (new)

```python
def sha256_file(path: Path, *, chunk_size: int = 1 << 20) -> str: ...
    # streamed digest; never loads the file whole (Streaming NFR / O4 anchor)
```

### `core/workspace.py` (new)

```python
@dataclass(frozen=True)
class WorkspaceMeta:
    schema_version: int
    dumpa_version: str
    input_path: str
    input_sha256: str
    input_size: int
    input_type: str          # 'apk' | 'xapk'
    created: str             # ISO-8601 UTC
    tool_versions: dict[str, str]

class Workspace:
    root: Path
    # path accessors
    @property
    def app_apk(self) -> Path: ...        # root/'app.apk'
    @property
    def extracted_dir(self) -> Path: ...  # root/'extracted'
    @property
    def dumps_dir(self) -> Path: ...      # root/'dumps'
    @property
    def reports_dir(self) -> Path: ...    # root/'reports'
    @property
    def meta_path(self) -> Path: ...      # root/'workspace.json'
    def read_meta(self) -> WorkspaceMeta | None: ...
    def write_meta(self, meta: WorkspaceMeta) -> None: ...
    def is_populated(self) -> bool: ...   # meta present AND extracted/ non-empty

@contextmanager
def open_workspace(path: Path | None, *, force: bool = False) -> Iterator[Workspace]:
    """path None -> ephemeral temp (wipe on exit unless DUMPA_KEEP_TMP).
       path given -> persistent; O5 reuse/force/refuse rules enforced by caller
       via the helpers below."""

def decide_reuse(ws: Workspace, input_sha256: str, *, force: bool) -> bool:
    """O5: True => reuse existing extraction; False => (re)build.
       Raises on sha256 mismatch-without-force and on clobber of a non-workspace dir."""
```

`open_workspace` owns lifetime only. Reuse/refuse policy (O5) is an explicit
helper so it is unit-testable without touching the filesystem lifecycle.

### `commands/analyze.py` (new) — FR2

Contract: `analyze(input_file: Path, *, workspace: Path | None, force: bool, signing: str | None) -> None`

```
1. input_sha256 = sha256_file(input_file)              # core/hashing
2. with open_workspace(workspace or default) as ws:    # O2 default ./<stem>-workspace
3.   if decide_reuse(ws, input_sha256, force): report & return   # O5
4.   if xapk: run convert pipeline -> ws.app_apk        # FR3, signing preset applied
      if apk:  link_or_copy(input_file -> ws.app_apk)
5.   safe_extract_zip(ws.app_apk, ws.extracted_dir)     # O1 canonical extract
6.   ws.write_meta(WorkspaceMeta(... tool_versions ...))
7.   report_output_apk(...) over ws.app_apk             # reuse existing reporter
```

### `commands/info.py` (new) — FR4

Contract: `info(input_file: Path) -> None`

- For `.xapk`: pull the base/main split to a small temp (reuse `classify` logic),
  run probes against it; read split ABI names from the xapk manifest. (O7)
- For `.apk`: probe directly.
- Probes (no apktool decode, no full extract):
  - `aapt dump badging` → package, versionName/Code, min/target SDK, ABIs
    (`native-code:`), permission **count** (count `uses-permission:` lines).
  - `apksigner verify --print-certs` → signer cert SHA-256, v1/v2/v3 schemes.
  - file size from `stat`.
- Output: a compact key→value block (human text). `--json` deferred to Phase 2.
- Failure-tolerant: missing aapt/apksigner degrades fields to `unknown`, never aborts.

### `tools/aapt.py` — extend

Add a richer parse alongside `badging()` (keep `badging()` for the convert
validator's narrow use):

```python
@dataclass(frozen=True)
class BadgingInfo:
    package: str | None
    version_name: str | None
    version_code: str | None
    min_sdk: str | None
    target_sdk: str | None
    abis: tuple[str, ...]
    permission_count: int

def read_badging(tool: ResolvedTool, apk: Path, timeout: int) -> BadgingInfo: ...
```

### `tools/apksigner.py` — extend

`verify()` already returns stdout. Add a pure parser (testable on captured text):

```python
@dataclass(frozen=True)
class SignerInfo:
    cert_sha256: str | None
    schemes: tuple[str, ...]   # subset of ('v1','v2','v3')

def parse_verify_output(text: str) -> SignerInfo: ...
```

Used by both `info` (FR4) and the signing-metadata report (FR5).

### `signing.py` + `core/config.py` — signing presets (FR5)

```python
# preset surface: unsigned | debug | custom | auto(default)
def resolve_signing(preset: str | None, config: Config, registry: ToolRegistry) -> SigningConfig | None:
    """auto  -> custom if [signing]/DUMPA_* configured else unsigned (current behavior)
       unsigned -> None
       custom   -> config.signing (error if not configured)
       debug    -> debug-keystore SigningConfig (O6)"""

def ensure_debug_keystore(registry: ToolRegistry) -> SigningConfig:
    """O6: reuse ~/.android/debug.keystore else generate a managed one via keytool."""
```

Signing metadata in the report: extend `report_output_apk` (or its caller) to run
`apksigner verify --print-certs`, parse via `parse_verify_output`, and log signer
cert SHA-256 + schemes + which preset was used.

## Refactors to Existing Code (FR3)

| File | Change |
|------|--------|
| `convert/pipeline.py` | `convert_xapk` accepts an optional `Workspace`. Build/merge in scratch; land merged apk at `ws.app_apk`. Ephemeral mode (no workspace) preserves today's "copy to cwd" UX; persistent mode leaves the apk in the workspace. Replace direct `working_tmp_dir(cwd)` use with the workspace primitive. |
| `commands/dump_il2cpp.py` | Accept `--workspace`. If populated → read il2cpp inputs from `ws.extracted_dir` (no re-extract), write to `ws.dumps_dir`. Else ephemeral (today). |
| `cli.py` | Add `analyze`, `info` commands; add `--workspace` to convert/dump-il2cpp/analyze; add `--signing` to convert/analyze; add `--force` to analyze. |

`convert`'s existing standalone CLI and `dump-il2cpp`'s defaults are unchanged
when the new flags are omitted (back-compat NFR).

## Data Flow

```
dumpa analyze game.xapk --workspace out/ --signing debug
        │
        ├─ sha256_file(game.xapk) ──────────────┐
        ▼                                        ▼
  open_workspace(out/) ── decide_reuse? ──reuse──► report & exit
        │ build                                   (O5)
        ▼
  convert pipeline (scratch) ── merge splits ──► out/app.apk  (signed: debug, O6)
        │
        ▼
  safe_extract_zip(app.apk) ──────────────────► out/extracted/   (O1)
        │
        ▼
  write workspace.json (input sha256, tools) ─► out/workspace.json (O4)

dumpa dump-il2cpp --workspace out/
        │
        ▼
  find_il2cpp_inputs(out/extracted) ──────────► out/dumps/   (no re-extract — FR3)
```

```
dumpa info game.apk            (fast path — no workspace, no apktool)
        │
        ├─ aapt dump badging ───────► package, versions, SDK, ABIs, perm count
        └─ apksigner verify --print-certs ─► cert sha256, v1/v2/v3 schemes
        ▼
  key→value block
```

## Module Plan (new vs touched)

- **New**: `core/hashing.py`, `core/workspace.py`, `commands/analyze.py`,
  `commands/info.py`.
- **Touched**: `tools/aapt.py` (`read_badging`), `tools/apksigner.py`
  (`parse_verify_output`), `signing.py` (presets + debug keystore),
  `core/config.py` (preset plumbing if needed), `convert/pipeline.py` (workspace),
  `commands/dump_il2cpp.py` (workspace), `cli.py` (wiring),
  `convert/validate.py` (signing metadata in report).

## Test Surface (for the TDD plan)

- `sha256_file` — known-vector digest; streams (no whole-file read).
- `decide_reuse` — match→reuse, mismatch→error, mismatch+force→rebuild,
  non-workspace dir→refuse, empty/absent→build.
- `parse_verify_output` — captured apksigner text → cert + schemes; unsigned text.
- `read_badging` — captured aapt text → all fields incl. ABIs + perm count.
- `resolve_signing` — each preset; auto-with/without config; custom-unconfigured error.
- `analyze` integration — xapk → workspace populated once; re-run reuses
  (one extraction on disk); `--force` rebuilds.
- Back-compat — `convert game.xapk` (no flags) unchanged; `dump-il2cpp` default unchanged.

## Constraints Honored

- No new third-party dependencies (stdlib `hashlib`/`json` + existing tools).
- Large files hardlinked via existing `link_or_copy`; digest streamed.
- Pure parsers (`parse_verify_output`, `read_badging`, `decide_reuse`) isolated
  from I/O for unit testing.
- No engine detection, no finding model, no caching layer (Phase 2/4/10).

## Next Step

`/sc:implement` (or `/deep-plan` for a sectioned TDD plan) — recommended build
order: `hashing` → `workspace` + `decide_reuse` → `analyze` (xapk path, reuse) →
refactor `dump-il2cpp` onto workspace → `aapt`/`apksigner` parsers → `info` →
signing presets + debug keystore + report metadata.
