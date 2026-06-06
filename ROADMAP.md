# Dumpa Roadmap

Dumpa is a CLI-focused reverse-engineering toolkit for APKs and XAPKs that you
own or have permission to inspect. The roadmap is scoped to game analysis,
privacy reporting, tracker inventory, protection inventory, and reproducible
APK/XAPK workflows.

Dumpa should report findings and evidence. It should not automatically bypass
protections, disable trackers, or modify app behavior unless a future feature is
explicitly designed and reviewed for that purpose. Inspecting assets of an app you
own or have permission to analyze — including decrypting your own game's script
bundles for reading — is in scope; circumventing protections on others' behalf is
not.

## Status Tracking

Use the checkboxes below to track implementation status:

- `[ ]` Planned or not started
- `[~]` Partially implemented (capability exists, but not as a first-class command
  or not fully verified)
- `[x]` Implemented and verified

## Current Status

The toolkit has been restructured from the original single-file `xapktoapk.py`
into an installable package (`src/dumpa`, Python 3.14+, Typer CLI) with a layered
design: `core/` (process, archive, fs, logging, errors, config, tool registry),
`tools/` (apktool/zipalign/apksigner/aapt adapters + il2cpp engines), and
`commands/`. Verified end-to-end on a real 195 MB Unity game: `convert` produced a
merged apk, then `dump-il2cpp` produced `dump.cs`/`il2cpp.h`/`script.json` via
Il2CppDumper. External tool commands are configurable (`[tools]` in `dumpa.toml`:
full path, bare command name, or command+args).

Shipped today: `convert`, `dump-il2cpp`, `doctor`; signing config + verification;
safe zip extraction; output validation; `DUMPA_*` env + TOML config.

## Scope

- Android games distributed as APK or XAPK.
- Static analysis first, with optional dynamic reporting through emulator or
  device workflows.
- Tracker and protection detection as inventory/reporting.
- Engine-aware analysis for Unity and other common game engines.
- Repacking and signing workflows for inspection, testing, and reproducibility.

## Architecture Foundations

These cross-cutting decisions should land early because every later phase depends
on them. Getting them right keeps phases 2–10 as "add a scanner" rather than "add
a subsystem."

- [x] **Unified finding model** — one `Finding` / `Evidence` / `Report` type in
  `core/report.py`. Every scanner is a pure function `(workspace) -> list[Finding]`;
  every exporter (JSON/Markdown/CSV/...) consumes the same model. No per-scanner
  report shapes. A `Finding` carries: kind, subject, confidence, evidence list, and
  zero-or-more locations (RVA, file offset, DEX class/method, manifest entry, asset
  path, domain). *(model shipped in Phase 2; JSON+Markdown exporters done)*
- [~] **Workspace as the canonical artifact** — extract an APK/XAPK once into a
  workspace directory; every command (convert, dump-il2cpp, scan-*, diff) reads and
  writes that one reproducible directory. No command re-extracts a 195 MB apk.
  *(`analyze` + `dump-il2cpp --workspace` share one extraction today; standalone
  `convert` still uses a private tmp; scan-*/diff not built yet)*
- [ ] **Content-hash caching** — cache key = input file hash + tool version + rule
  version. This is what makes re-runs, `load` (batch), and `diff` cheap; build it
  with the workspace, not later.
- [ ] **Stream large artifacts** — `script.json` and `dump.cs` are tens to hundreds
  of MB on real games. Scanners must stream / scan line-by-line over big files, never
  load them whole into memory.
- [x] **Rules are TOML** — reuse the existing config stack (stdlib `tomllib`, zero
  extra deps). One parser, one mental model. (Reach for YAML only if a rule type
  genuinely needs its ergonomics.) *(shipped in Phase 3: `core/rules.py` + bundles
  under `dumpa/rules/`)*

## Technical Notes

- RVA applies to native libraries such as `lib/<abi>/*.so`.
- Java, Kotlin, and DEX findings should report class, method, field, DEX file,
  smali path, and bytecode or file offset instead of RVA.
- Reports should include evidence for every finding so users can audit false
  positives and understand why a tracker, protection, or engine was detected.
- Every report records the input file hash up front, so findings are tied to one
  exact artifact.

## Core Capabilities

- [~] Unpack APK and XAPK files. *(done inside `convert`/`dump-il2cpp`/`analyze`; no
  standalone `unpack` command yet)*
- [x] Convert XAPK files to APK files. *(verified on a real 195 MB Unity game)*
- [x] Dump IL2CPP metadata and generated artifacts. *(verified via Il2CppDumper)*
- [x] Repack APK files. *(apktool rebuild inside the convert pipeline)*
- [ ] Search for protections within the APK and report corresponding native RVAs,
  file offsets, and DEX locations where applicable. *(presence detection can land
  early; RVAs/offsets depend on native analysis — see Phase 7)*
- [ ] Search for trackers within the APK and report corresponding native RVAs, file
  offsets, DEX locations, manifest entries, domains, and matched signatures.
- [ ] Use pattern matching and regex to find useful patterns in `dump.cs`.
- [ ] Select patterns on a game-type basis.
- [ ] Detect or fetch game types for an APK.
- [ ] Compare game-type-specific regex patterns against `dump.cs`.
- [ ] Add radare2 support to automatically scan native regions. *(see Phase 7)*
- [~] `dumpa info` — fast triage summary (package, version, ABIs, engine, size,
  signer cert, permission count) with no deep analysis. *(all fields except engine,
  which is deferred to Phase 4)*
- [~] Report APK signing info — signer certificate SHA-256, v1/v2/v3 schemes, and
  debug-certificate detection. *(cert SHA-256 + schemes done via `info`; debug-cert
  detection not yet)*
- [ ] Structured manifest dump (permissions, components + exported flags, min/target
  SDK) as a shared primitive used by engine detection and the manifest privacy audit.

## Game Engine Support

Engine **detection** is cheap and data-driven (file layout, libraries, assets,
package names) and ships broadly. Engine-specific **deep helpers** are expensive, so
they are built narrowly; the rest stay detection-only via rule bundles rather than
half-finished modules.

Deep-helper engines (initial): **Unity**, **Cocos2d-x** (incl. script decryption),
**Godot**.

Detection-only (rule bundle; no deep module yet). All have detection rules in
`dumpa/rules/engines.toml` as of Phase 3; `[~]` until auto-detection is wired into
`analyze` in Phase 4.

- [~] Defold
- [~] Flutter
- [~] GameMaker
- [~] Kivy
- [~] libGDX
- [~] Ren'Py
- [~] RPG Maker
- [~] Unreal
- [~] Corona / Solar2D

Deep-helper engines:

- [~] Unity *(detection implicit via il2cpp inputs; il2cpp dump done — deeper helpers
  in Phase 4)*
- [ ] Cocos2d-x *(detection + encrypted script inspection — Phase 4)*
- [ ] Godot *(detection + `.pck` inspection — Phase 4)*

Each engine module should document the files, assets, libraries, and config
locations it uses for detection.

## Phased Plan

### Phase 1: APK/XAPK Foundation

- [~] Stabilize unpacking for APK and XAPK inputs.
- [x] Keep XAPK-to-APK conversion as a first-class command.
- [x] Preserve safe archive extraction and output validation.
- [x] Support APK repacking, zipalign, signing, and signature verification.
  *(signing exercised end-to-end with a generated debug keystore: sign -> v1/v2/v3
  verify -> signer cert SHA-256 parsed)*
- [x] Add the workspace as the canonical artifact (see Architecture Foundations):
  - `dumpa analyze app.xapk --workspace out/`
  - Keep extracted files, dumps, and reports in one reproducible directory.
  *(`analyze` extracts once into `<root>/{app.apk,extracted,dumps,reports}` plus a
  `workspace.json` marker; `dump-il2cpp --workspace` reuses the extraction. Content-hash
  caching deferred to Phase 10; reuse keys on the recorded input SHA-256.)*
- [x] Add `dumpa info` for fast triage without a full analysis.
  *(package, version, min/target SDK, ABIs, permission count, signer cert SHA-256,
  signing schemes — no apktool decode; engine omitted, see Phase 4)*
- [x] Add signing/profile presets:
  - [x] unsigned output
  - [x] debug signing *(reuses `~/.android/debug.keystore` or generates a managed one)*
  - [x] custom keystore signing *(via [signing]/DUMPA_* config)*
  - [x] reproducible signing metadata in reports *(cert SHA-256 + schemes logged)*

### Phase 2: Reporting Backbone

- [x] Implement the unified finding model (`core/report.py`) before any scanner.
  *(pure `Finding`/`Evidence`/`Location`/`AppFacts`/`Report` + `Confidence`, with
  to_dict/from_dict, JSON read/write, and a Markdown renderer; built by
  `dumpa.reporting.build_report`)*
- [~] Add a unified analysis report with:
  - [x] input file hash
  - [x] package name and version
  - [ ] detected game engine *(field present; populated in Phase 4)*
  - [x] ABIs
  - [x] permissions
  - [x] signer certificate and signing schemes
  - [ ] trackers *(findings list; scanner is Phase 5)*
  - [ ] protections *(findings list; scanner is Phase 7)*
  - [ ] native RVAs and file offsets *(Location supports them; scanner is Phase 7)*
  - [ ] DEX locations *(Location supports them; scanner is Phase 8)*
  - [x] hashes
  - [x] tool versions
  - [x] warnings
- [~] Support report formats:
  - [x] JSON for automation *(the spine)*
  - [x] Markdown for reading
  - [ ] HTML for reading
  - [ ] CSV for tracker and domain lists *(deferred until the Phase 5 tracker/domain
    lists exist)*
  - [ ] SARIF only if/when a code-scanning consumer needs it (defer; awkward fit for
    privacy reports)
- [~] Save an evidence bundle with:
  *(the `Evidence` model carries snippet/file-hash/offset/RVA/tool/rule-version;
  a standalone evidence-bundle directory is not written yet)*
  - matched snippets
  - file hashes
  - offsets
  - RVAs
  - tool versions
  - rule versions
- [~] Add `dumpa export --format csv/json/html`. *(`dumpa export <workspace>
  --format json|md [--out]` shipped; csv/html not yet)*
- [~] Add golden-sample regression fixtures: known inputs with expected findings, so
  rule and parser changes can't silently regress. *(report-model round-trip +
  build-report fixtures added; a real-apk golden sample is still pending)*

### Phase 3: Rule and Signature System

- [~] Add TOML rule bundles for:
  - [x] game engines *(`dumpa/rules/engines.toml`, 12 engines)*
  - [ ] trackers *(needs string/dex matchers — Phase 5)*
  - [ ] protections *(needs native/string matchers — Phase 7)*
  - [ ] native symbols *(matcher kind not implemented yet — Phase 7)*
  - [ ] smali strings *(matcher kind not implemented yet — Phase 8)*
  - [x] file paths *(the `path_glob` matcher kind)*
  - [ ] `dump.cs` regexes *(matcher kind not implemented yet)*
  - [ ] YARA-style byte patterns *(matcher kind not implemented yet — Phase 7)*
- [x] Add `dumpa rules test` to test custom regex/signature rules against an APK,
  extracted workspace, or `dump.cs`. *(workspace dir, extracted dir, or .apk; `dump.cs`
  target arrives with the dump.cs matcher kind)*
- [x] Add `dumpa rules explain` to show why a tracker, protection, or engine was
  detected. *(prints a subject's matchers + bundle provenance)*
- [ ] Add `dumpa update-signatures` to update tracker, protection, and game-engine
  rule bundles. Updates are explicit and versioned (never silent), to preserve
  reproducibility.
- [x] Store source, version, and update date for every imported signature bundle.
  *([bundle] name/version/source/updated, surfaced by `dumpa rules list`)*
- [x] Add false-positive controls with finding states:
  - [x] present
  - [x] referenced
  - [x] initialized
  - [x] network-observed
  *(`FindingState` enum on every Finding; path-glob detections report `present`,
  later scanners set the stronger states)*

### Phase 4: Engine-Aware Analysis

- [ ] Add engine auto-detection using:
  - manifest entries
  - assets
  - native libraries
  - package names
  - file layout
  - config files
- [ ] Add Unity-specific helpers:
  - metadata version detection
  - managed/native backend detection
  - `global-metadata.dat` validation
  - per-ABI IL2CPP dump selection *(arch selection already implemented)*
  - Unity plugin scanner
  - `Assets/Plugins/Android` scanner
  - Unity services detection
  - Addressables catalog detection
  - Firebase config detection
  - remote config detection
- [ ] Add Cocos2d-x helpers:
  - detect engine (`libcocos2d*.so`, `assets/`, `src/`, jsc/luac layout) and version
  - locate compiled/encrypted script bundles (`*.jsc`, `*.luac`)
  - detect the XXTEA key when present in the native library or assets
  - decrypt script bundles for inspection when a key is provided or found, reporting
    the key source as evidence
  - JavaScript and Lua asset scanning
  - native library detection
- [ ] Add Godot helpers:
  - detect engine and Godot version
  - `.pck` discovery (standalone and embedded-in-binary)
  - packed resource listing and optional extraction
  - GDScript bytecode (`.gdc`) and `project.godot`/`project.binary` config scanning
- [ ] Detection-only engines (Defold, Flutter, GameMaker, Kivy, libGDX, Ren'Py,
  RPG Maker, Unreal, Corona/Solar2D): ship a detection rule bundle that documents the
  files/libraries/assets used to identify the engine. No deep module until demand
  justifies it.

### Phase 5: Tracker-Focused Privacy Inventory

- [ ] Add a tracker evidence model (a specialization of the unified finding model).
  Every tracker finding should include evidence such as:
  - matched class or package
  - native library
  - string
  - domain
  - manifest component
  - DEX method
  - asset file
  - native RVA or file offset
- [ ] Add confidence scoring:
  - high
  - medium
  - low
- [ ] Add tracker taxonomy:
  - ads
  - analytics
  - attribution
  - crash reporting
  - remote config
  - push messaging
  - A/B testing
  - social login or sharing
  - anti-fraud
  - consent management
  - ad mediation
- [ ] Add SDK owner mapping so package names resolve to companies, products,
  purposes, and likely data use.
- [ ] Add a game ad mediation graph for:
  - AdMob
  - AppLovin MAX
  - Unity LevelPlay / ironSource
  - Unity Ads
  - Vungle / Liftoff
  - Chartboost
  - Mintegral
  - Pangle
  - Tapjoy
  - Meta Audience Network
- [ ] Add tracker signature database importers where licensing and data access allow:
  - Exodus Privacy: <https://github.com/Exodus-Privacy/exodus>
  - TrackerControl: <https://github.com/TrackerControl/tracker-control-android>
  - AppBrain SDK statistics:
    <https://www.appbrain.com/stats/libraries/tag/analytics/android-analytics-libraries>
- [ ] Add an ad SDK density score:
  - trackers per MB
  - ad SDKs per game engine
  - mediation adapter count
  - unique tracker company count

### Phase 6: Static Privacy Analysis

- [ ] Add a data-access capability report for APIs and permissions tied to:
  - Advertising ID / `AD_ID`
  - Android ID
  - location
  - contacts
  - accounts
  - microphone and camera
  - clipboard
  - sensors
  - installed packages
  - external storage
  - Bluetooth, Wi-Fi, and network state
- [ ] Add Advertising ID analysis:
  - flag `com.google.android.gms.permission.AD_ID`
  - detect calls into advertising ID APIs
  - detect SDKs that may add `AD_ID` through manifest merging
  - reference:
    <https://support.google.com/googleplay/android-developer/answer/6048248?hl=en-EN>
- [ ] Add manifest privacy audit (built on the Phase 1/2 structured manifest dump):
  - exported components
  - background services
  - receivers
  - boot receivers
  - install referrer receivers
  - deep links
  - backup/debuggable flags
  - suspicious permission combinations
- [ ] Add endpoint extraction from:
  - DEX
  - native libraries
  - resources
  - Unity assets
  - Unreal and Godot configs
  - JSON, XML, and protobuf-like blobs
- [ ] Extract and report:
  - domains
  - URLs
  - IPs
  - API paths
  - websocket endpoints
  - Firebase endpoints
  - remote config URLs
  - CDN URLs
  - ad auction endpoints
- [ ] Add optional domain ownership enrichment (offline-first; networked lookups are
  opt-in and never required for a report):
  - tracker company
  - ASN
  - country
  - category
- [ ] Add optional Google Play Data Safety comparison:
  - compare observed trackers, permissions, and data-access indicators against
    store disclosures
  - reference:
    <https://support.google.com/googleplay/android-developer/answer/10787469?hl=en>

### Phase 7: Native Analysis and radare2 Integration

- [ ] Add multi-ABI native analysis for every `lib/<abi>/*.so`.
- [ ] Report native metadata:
  - architecture
  - symbols
  - exports
  - imports
  - sections
  - strings
  - RVAs
  - file offsets
  - suspicious regions
- [ ] Add radare2-backed region scanning. *(this is the home for all radare2 support)*
- [ ] Add protection signatures for native libraries, smali markers, assets, and
  strings. *(this unblocks the protection-RVA reporting promised in Core Capabilities)*
- [ ] Add native string reports grouped by library and ABI.
- [ ] Add a cross-reference index across:
  - manifest
  - smali
  - Java/Kotlin decompile output
  - native strings
  - `dump.cs`
  - resources
  - assets

### Phase 8: Decompilation and Low-Level Inspection

- [ ] Add JADX integration for Java/Kotlin decompilation.
- [ ] Add baksmali/smali support for low-level DEX inspection and rebuild workflows.
- [ ] Add resource table inspection for:
  - strings
  - layouts
  - raw assets
  - unknown binary blobs
- [ ] Detect hardcoded:
  - URLs
  - API keys
  - endpoints
  - analytics IDs
  - ad network IDs
  - cloud storage buckets

### Phase 9: Dynamic Reporting (optional companion)

Dynamic analysis is an order of magnitude more complex than the static core
(device/emulator management, traffic capture, certificate pinning). Keep it
**optional and isolated** — ideally a separate companion module that feeds findings
back into the same report model — so device plumbing never leaks into the static
core.

- [ ] Add optional emulator traffic profile:
  - run the game in an emulator
  - capture DNS, SNI, and HTTP metadata
  - report contacted hosts
  - do not bypass certificate pinning by default
  - report when certificate pinning prevents deeper inspection
- [ ] Add first-launch privacy trace:
  - contacts before consent
  - contacts before login
  - contacts before gameplay
- [ ] Add scenario-based runs:
  - cold launch
  - deny all permissions
  - grant location
  - no network
  - after tutorial
  - after rewarded ad
- [ ] Add runtime SDK initialization detection using:
  - logs
  - loaded classes
  - loaded native libraries
  - network events
- [ ] Add optional `adb` helper to install, launch, capture logs, and verify package
  and activity after repack.

### Phase 10: Comparison, Batch, and Export Workflows

- [ ] Add diff mode:
  - `dumpa diff old.apk new.apk`
  - changed files
  - changed native symbols
  - changed permissions
  - new trackers
  - removed trackers
  - new protections
  - changed Unity methods
- [ ] Add version tracker diffing that answers:
  - Which trackers appeared in this update?
  - Which tracker companies were added or removed?
  - Which new domains appeared?
- [ ] Add `dumpa load` to analyze a directory of APK/XAPK files and produce one
  combined report. *(cheap once content-hash caching exists)*
- [ ] Add blocklist export for observed tracker domains:
  - Pi-hole
  - NextDNS
  - AdGuard
  - RethinkDNS
  - TrackerControl-compatible formats
- [ ] Add `dumpa clean` to remove temporary and workspace artifacts safely.

## Command Ideas

- [ ] `dumpa unpack app.apk`
- [ ] `dumpa unpack app.xapk`
- [x] `dumpa convert app.xapk`
- [ ] `dumpa repack workspace/`
- [x] `dumpa info app.apk`
- [x] `dumpa analyze app.apk --workspace out/`
- [x] `dumpa analyze app.xapk --workspace out/`
- [x] `dumpa dump-il2cpp app.apk`
- [ ] `dumpa scan-trackers app.apk`
- [ ] `dumpa scan-protections app.apk`
- [ ] `dumpa scan-native app.apk --tool radare2`
- [x] `dumpa rules test app.apk`
- [~] `dumpa rules explain tracker firebase-analytics` *(`rules explain <subject>`
  shipped; the tracker bundle it would explain arrives in Phase 5)*
- [ ] `dumpa update-signatures`
- [ ] `dumpa diff old.apk new.apk`
- [ ] `dumpa load samples/`
- [x] `dumpa export --format json`
- [~] `dumpa doctor` *(basic check shipped; `--full` below is planned)*
- [ ] `dumpa doctor --full`
- [ ] `dumpa clean workspace/`

## Doctor Checks

`dumpa doctor` already verifies the tools below marked `[x]`. `dumpa doctor --full`
should additionally verify the rest:

- [ ] Python runtime
- [~] Java runtime *(checked indirectly via keytool)*
- [ ] Android SDK paths
- [x] apktool
- [x] zipalign
- [x] apksigner
- [x] aapt or aapt2
- [ ] JADX
- [ ] baksmali/smali
- [ ] radare2
- [x] IL2CPP tools *(Il2CppDumper / Il2CppInspector)*
- [ ] adb
- [~] signing config *(config layer exists; a dedicated readiness check is planned)*
- [ ] configured rule bundles
- [ ] signature database version

## Success Criteria

- [ ] A user can analyze an APK or XAPK and receive a readable privacy report without
  manually unpacking the app.
- [ ] Every tracker and protection finding includes evidence and confidence.
- [ ] Native findings include RVAs and file offsets.
- [ ] DEX findings include class, method, field, file, and bytecode or file offset.
- [ ] Engine detection explains why each engine was detected.
- [ ] Reports are reproducible because input hashes, tool versions, and rule versions
  are recorded.
- [ ] Analysis of a real game does not exhaust memory — large artifacts are streamed.
- [ ] Golden-sample fixtures guard against rule and parser regressions.
- [ ] Batch and diff workflows make tracker changes across game versions obvious.
- [ ] Dynamic analysis remains optional and reporting-only.
