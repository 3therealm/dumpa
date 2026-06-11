# Design — Streaming + `dump.cs` Pattern Matching

Status: design (no implementation). Follows `req-dumpcs-patterns` brief.
Type: component + data-model + integration design.

## 1. Summary

Add genre-aware IL2CPP `dump.cs` scanning to `dumpa`:

1. **Auto-dump** — `analyze` runs `dump-il2cpp` into `dumps/` when Unity+IL2CPP is detected.
2. **Game-type detection** — resolve the package's Google Play genre (networked, cached) → map to pattern categories.
3. **dump.cs scanner** — stream genre-selected regex bundles over `dumps/dump.cs` (+ `script.json`), emit findings.
4. **Pattern library** — port the DumpExplorer JSON patterns (general/match3/rpg/strategy) to TOML rule bundles + add anti-cheat and obfuscation categories.

Design principle held from the codebase: detection is **data (TOML bundles)**, scanning is a **pure `(ws)->findings` scanner**, streaming reuses the **existing chunked `_scan_content`**.

## 2. Component overview

```
                         dumpa analyze
                              │
              build_workspace │  (extract once)
                              ▼
                    ┌───────────────────┐
                    │   auto-dump gate   │  find_il2cpp_inputs(extracted)
                    │  (Unity+IL2CPP?)   │──► dump-il2cpp ──► dumps/dump.cs
                    └───────────────────┘     (skip if --no-dump / no tool / cached)
                              │
                       build_report
                              │  run_all(ws)
        ┌─────────────────────┼───────────────────────────────┐
        ▼                     ▼                                ▼
  engine scanner       gametype scanner                  dumpcs scanner
 (engines.toml)     core.gametype.resolve()          core.gametype.resolve()  ← shared, cached
        │           ├─ Play fetch (cached)            select categories by genre
        │           └─ writes dumps/gametype.json     load dumpcs_*.toml bundles
        │           emits game-type findings          _scan_content(dumps/, regexes)
        │                     │                        emits dumpcs findings
        └─────────────────────┴───────────────────────────────┘
                              │
                  AppFacts.game_types + findings  ──►  report.json
```

Shared resolver (`core/gametype.py`) is called by both the gametype scanner and the dumpcs scanner; it memoizes via a `dumps/gametype.json` sidecar + a `cache/playstore/<pkg>.json` network cache, so the Play fetch happens once per workspace.

## 3. Data model changes

### 3.1 `core/report.py`

`AppFacts` gains one field (additive; `from_dict` already uses `.get`, so old reports still load):

```python
game_types: list[str] = field(default_factory=_str_list)   # Play genres, primary first
```

`to_dict`/`from_dict` updated. `Report.schema_version` bumped (cosmetic; readers tolerant).

New **finding kinds** (no model change — `kind` is a free string):

| kind | producer | subject | evidence |
|---|---|---|---|
| `game-type` | gametype scanner | Play genre label (e.g. `Puzzle`) | Play genreId + listing URL + fetch date |
| `dumpcs` | dumpcs scanner | pattern name (e.g. `currency-hard`) | matched text + dump.cs offset + bundle version |

`dumpcs` findings locate via `Location(file_path="dumps/dump.cs", file_offset=…)`. State = `PRESENT` (a symbol-name match is presence, not behavior).

## 4. Rule-engine extension (`core/rules.py`)

Minimal, backward-compatible changes. Existing extracted-rooted bundles untouched.

### 4.1 `Rule` dataclass — one new field

```python
case_insensitive: bool = False     # compile regex with re.IGNORECASE
```

Parser: read optional bool `case_insensitive` (default False). DumpExplorer's `case_sensitive: false` maps to `case_insensitive = true`.

### 4.2 Regex compilation — honor the flag + dedupe by (pattern, flag)

`_apply_content_rules` currently keys `regexes` by pattern string. Change key to `(pattern, flags)` to avoid collisions when the same source appears case-sensitive and -insensitive:

```python
flags = re.IGNORECASE if rule.case_insensitive else 0
regexes[(p, flags)] = re.compile(p.encode(), flags)
```

`Rule.keys` / `_content_finding` keep using the bare pattern string for evidence labels; the compiled map is an internal detail.

### 4.3 Rooted scanning — expose a public helper

`_scan_content`'s 4th param is already the rel-base (`extracted_dir`). Rename it to `root` (semantic only) and add a thin public entry the dumpcs scanner calls with a non-extracted root:

```python
def scan_content_rules(rules: list[Rule], bundle: RuleBundle, root: Path) -> list[Finding]:
    """Apply content rules rooted at `root` (extracted/ OR dumps/). Reuses _scan_content."""
```

`apply_bundle` keeps rooting at `extracted/` for the existing scanners. No mixed-root bundle is allowed — a dumpcs bundle is scanned only at `dumps/`.

### 4.4 Target aliases

The dumpcs scanner sets `default_targets = ("dump.cs", "script.json")`, resolved against `dumps/`. A rule may still name its own `targets` (e.g. `["dump.cs"]`). No blanket `dumps/**` (per decision #4). Aliases are explicit filenames, not a new glob root.

### 4.5 New rule `kind`

dumpcs bundles use `kind = "dumpcs"`. The kind is carried onto the Finding (free string), so no enum change. Bundles add a per-rule selector:

```toml
game_types = ["match3"]      # which mapped categories select this rule; omit = always-on
```

`general`, `anti-cheat`, `obfuscation` rules omit `game_types` (always run). Genre-specific rules list their category. The dumpcs scanner filters rules by the resolved category set before scanning.

## 5. Pattern library port (`rules/dumpcs_*.toml`)

JSON (DumpExplorer) → TOML (dumpa) mapping:

| DumpExplorer JSON | dumpa TOML rule | note |
|---|---|---|
| `categories[].patterns[].name` | `subject` | pattern id |
| `pattern` | `regex = [ … ]` | single-element list |
| `description` | (Evidence description, auto) | |
| `case_sensitive: false` | `case_insensitive = true` | all source patterns are insensitive |
| `category` / file category | `game_types = [...]` + bundle name | |
| `engines: ["unity-il2cpp"]` | bundle scoped to dump.cs (IL2CPP only) | engine gate implicit — dump.cs only exists for IL2CPP |
| `confidence` | `confidence` (default `medium`) | |

Bundles to ship (one TOML per category file, `[bundle]` versioned/stamped):

- `dumpcs_general.toml` — 15 patterns (always-on): player-manager, game-manager, save-system, settings-prefs, network-online, authentication, analytics-tracking, monetization-iap, ads-advertising, ui-system, audio-sound, tutorial-onboarding, achievement, notification-push, debug-cheat.
- `dumpcs_match3.toml` — 14: boosters-activate/create, currency-hard/soft, lives-system, level-progress, score-system, moves-counter, board-grid, match-detection, combo-system, special-blocks, daily-challenge, tournament. `game_types=["match3"]`.
- `dumpcs_rpg.toml` — 12: character-stats, health-system, mana-system, experience-level, inventory-management, combat-system, skill-ability, quest-system, dialogue-narrative, save-load, party-management, companion-ai. `game_types=["rpg"]`.
- `dumpcs_strategy.toml` — 10: resource-production/storage, building-system, tech-tree, unit-training, combat-military, map-territory, alliance-diplomacy, trade-market, time-speed. `game_types=["strategy"]`.
- `dumpcs_anticheat.toml` — NEW (always-on): integrity-check, tamper-detect, root-detect, emulator-detect, debugger-detect, speed-hack-detect, memory-edit-detect, signature-verify.
- `dumpcs_obfuscation.toml` — NEW (always-on): name-mangling, string-encryption, reflection-heavy, control-flow-flatten, packer-stub, dynamic-loading markers.

Example ported rule:

```toml
[bundle]
name = "dumpcs_match3"
version = "2026.06.1"
source = "ported from DumpExplorer patterns/match3.json"
updated = "2026-06-08"

[[rule]]
kind = "dumpcs"
subject = "currency-hard"
confidence = "high"
game_types = ["match3"]
case_insensitive = true
targets = ["dump.cs"]
regex = ['(Gem|Diamond|Crystal|Gold).*((Manager|Add|Spend|Get|Set|Balance|Wallet))']
```

## 6. Game-type detection (`core/gametype.py` + `core/playstore.py`)

### 6.1 `core/playstore.py` — networked, opt-in, cached

```python
@dataclass(frozen=True)
class PlayListing:
    package: str
    genre: str          # human label, e.g. "Puzzle"
    genre_id: str       # e.g. "GAME_PUZZLE"
    url: str
    fetched: str        # ISO-8601 UTC

def fetch_listing(package: str, *, cache_dir: Path, allow_network: bool,
                  timeout: int) -> PlayListing | None:
    """Read cache/playstore/<pkg>.json if present; else fetch the Play listing
    (stdlib urllib) and cache it. None when offline / not listed / network off."""
```

- Source: the public Play store listing page for `id=<package>`; parse the `genreId`/`genre` from the page metadata. Stdlib `urllib` only — no new dependency.
- Cache: `<ws>/cache/playstore/<package>.json` (TTL-checked; default 30 days). Cache is the reproducibility anchor — a stored listing replays identically offline.
- Failure modes (offline, 404, parse fail) → `None`, never raises into the scan.

### 6.2 `core/gametype.py` — resolve + map

```python
@dataclass(frozen=True)
class GameType:
    genre: str
    genre_id: str
    categories: tuple[str, ...]   # mapped dumpcs categories, e.g. ("match3",)
    source_url: str
    fetched: str

def resolve_game_types(ws: Workspace, *, allow_network: bool,
                       timeout: int) -> list[GameType]:
    """Resolve via dumps/gametype.json sidecar if present; else look up package →
    Play listing → genre → categories, write the sidecar, return it."""
```

- Reads package from `load_manifest(ws)` (badging fallback).
- Sidecar `dumps/gametype.json` memoizes the resolution so the gametype scanner and dumpcs scanner share one fetch.
- Genre→category map: a small in-repo table (`rules/gametype_map.toml`):

```toml
[map]
GAME_PUZZLE        = ["match3"]
GAME_ROLE_PLAYING  = ["rpg"]
GAME_STRATEGY      = ["strategy"]
GAME_CARD          = ["strategy"]
# unmapped genres → [] → general + anti-cheat + obfuscation only
```

- Always-on categories (`general`, `anti-cheat`, `obfuscation`) are NOT in the map — the dumpcs scanner unions them in unconditionally.

## 7. Scanners

### 7.1 `scanners/gametype.py`

```python
def scan(ws: Workspace) -> list[Finding]:
    # allow_network/timeout pulled from config (see §9)
    types = resolve_game_types(ws, allow_network=…, timeout=…)
    # one game-type finding per resolved genre, evidence = url + genre_id + fetched
```

No-ops (returns `[]`) when package unknown or resolution returns nothing.

### 7.2 `scanners/dumpcs.py`

```python
const_dumpcs_bundles = ("dumpcs_general", "dumpcs_match3", "dumpcs_rpg",
                        "dumpcs_strategy", "dumpcs_anticheat", "dumpcs_obfuscation")

def scan(ws: Workspace) -> list[Finding]:
    if not (ws.dumps_dir / "dump.cs").is_file():
        return []                      # no dump → no-op
    types = resolve_game_types(ws, …)  # shared, sidecar-cached
    selected = {"general", "anti-cheat", "obfuscation"}
    for t in types: selected.update(t.categories)
    findings = []
    for name in const_dumpcs_bundles:
        bundle = load_builtin(name)
        rules = [r for r in bundle.rules if _selected(r, selected)]
        findings += scan_content_rules(rules, bundle, ws.dumps_dir)
    return findings
```

`_selected(rule, selected)` = rule has no `game_types` (always-on) OR any of its `game_types` ∈ `selected`.

### 7.3 Registration (`scanners/__init__.py`)

Append after `dex`, before/after `endpoint` — order only matters for human-readable grouping:

```python
ScannerSpec("gametype", gametype.scan),
ScannerSpec("dumpcs", dumpcs.scan, ("dumpcs_general","dumpcs_match3","dumpcs_rpg",
                                    "dumpcs_strategy","dumpcs_anticheat","dumpcs_obfuscation")),
```

Both are unconditional scanners (they self-no-op), so no `UNITY_SPEC`-style special casing is needed.

## 8. Auto-dump integration (`commands/analyze.py`)

New step in `analyze()` after `build_workspace`, before `_report_workspace`:

```python
def _maybe_autodump(registry, ws, config, *, enabled: bool) -> None:
    if not enabled: return
    if (ws.dumps_dir / "dump.cs").is_file(): return        # already dumped
    if not find_il2cpp_inputs(ws.extracted_dir, None): return   # not IL2CPP
    try:
        eng = get_engine(config.il2cpp_engine)
        tool = registry.resolve(eng.tool_name)
    except ToolNotFoundError:
        logger.warning("auto-dump skipped: %s not found", config.il2cpp_engine)
        return
    _run_dump(eng, config.il2cpp_engine, tool, ws.extracted_dir, None, ws.dumps_dir)
```

- Gated by a new `--no-dump` flag (default: auto-dump ON). Reuses `_run_dump` from `commands/dump_il2cpp.py` (extract the helper to a shared module or import it).
- Only in `analyze` (persistent workspace). `report_for_input` (diff/load, ephemeral) does **not** auto-dump — keeps batch/diff fast; the dumpcs scanner just no-ops there. Documented limitation.
- Records `auto_dump=true` + il2cpp engine/version into `WorkspaceMeta.build_options` for reproducibility.

## 9. Config / CLI surface

`dumpa.toml` `[analysis]` + `DUMPA_*` env (reuse `core/config`):

| setting | default | purpose |
|---|---|---|
| `auto_dump` / `--no-dump` | on | run dump-il2cpp during analyze |
| `play_lookup` / `DUMPA_PLAY_LOOKUP` | on | allow networked Play genre fetch |
| `play_cache_ttl_days` | 30 | Play listing cache TTL |
| `play_timeout` | reuse validation timeout | network timeout |

`--no-network` (global) forces `play_lookup=off` → general-only patterns, fully offline.

## 10. Caching & reproducibility

- **dumpcs scanner cache key** must include the **dump-tool version** (dump.cs is derived). Extend the scanner's bundle-version map with a synthetic entry `il2cpp:<engine-version>` so a new dumper invalidates cached dumpcs findings. Requires threading the resolved il2cpp version into `_run_spec` for the dumpcs spec (small extension to `ScannerSpec`/`compute_scanner_key`).
- **gametype**: not keyed on input hash (genre is external + time-varying). The `cache/playstore/<pkg>.json` disk cache + TTL is the reproducibility anchor; every game-type/dumpcs report records the `fetched` date in evidence so a reader can see when the genre was observed.
- **Streaming**: `_scan_content` reads 1 MiB chunks with overlap — already bounded memory; dump.cs (100s MB) is fine. Lift `const_max_content_scan_bytes` (currently 512 MiB) only if a real dump exceeds it; revisit with a measured sample.

## 11. Sequence — `dumpa analyze game.apk --workspace out/`

```
analyze → build_workspace            (extract once)
        → _maybe_autodump            find_il2cpp_inputs → dump-il2cpp → dumps/dump.cs
        → build_report → run_all
              engine.scan            engines.toml over extracted/
              gametype.scan          resolve_game_types → Play fetch (cache) → dumps/gametype.json
                                     → emits game-type findings
              dumpcs.scan            reads sidecar → select categories →
                                     scan_content_rules(dumpcs_*, dumps/) → dumpcs findings
        → AppFacts.game_types = [genres]   (from game-type findings, primary first)
        → write report.json
```

## 12. Test plan

- **Unit, rules**: `case_insensitive` compile + (pattern,flag) dedupe; `scan_content_rules` rooted at a non-extracted dir; target-alias resolution.
- **Unit, gametype**: genre→category map (mapped, unmapped→general-only); sidecar read/write; offline → `[]`.
- **Unit, playstore**: cache hit (no network); parse a fixture listing page; 404/parse-fail → None. Network calls mocked — no live Play hits in tests.
- **Unit, dumpcs scanner**: no dump.cs → `[]`; category selection by resolved genre; findings carry dump.cs offset + bundle version.
- **Bundle validation**: every `dumpcs_*.toml` parses; all 51+ ported patterns compile as regex; `dumpa rules test` works against a fixture dump.cs.
- **Streaming**: synthetic large dump.cs (e.g. 600 MB) scanned within bounded RSS (assert peak memory).
- **Integration**: fixture Unity workspace → auto-dump stub → dumpcs findings in report.json; `--no-dump` and `--no-network` paths.

## 13. New / changed files

New:
- `core/playstore.py`, `core/gametype.py`
- `scanners/gametype.py`, `scanners/dumpcs.py`
- `rules/dumpcs_general.toml`, `dumpcs_match3.toml`, `dumpcs_rpg.toml`, `dumpcs_strategy.toml`, `dumpcs_anticheat.toml`, `dumpcs_obfuscation.toml`, `rules/gametype_map.toml`

Changed:
- `core/rules.py` — `case_insensitive` field + parse; (pattern,flag) regex dedupe; `scan_content_rules` public helper; rename `_scan_content` root param.
- `core/report.py` — `AppFacts.game_types` + (de)serialization; schema bump.
- `core/workspace.py` — `gametype.json` / `playstore/` path accessors (sidecar + cache).
- `scanners/__init__.py` — register gametype + dumpcs; dumpcs cache key += il2cpp version.
- `commands/analyze.py` — `_maybe_autodump` + `--no-dump`.
- `commands/dump_il2cpp.py` — extract `_run_dump` to a shared module for reuse.
- `core/config.py` + CLI — `auto_dump`, `play_lookup`, TTL, timeout, `--no-network`.
- `reporting.py` — populate `AppFacts.game_types` from findings.

## 14. Risks / open (for implementation)

- **Play page parsing is brittle** — the listing HTML can change. Isolate the parse in `playstore.py`, fixture-test it, fail soft to `None`. (A future structured source can drop in behind the same interface.)
- **Symbol-name vs raw-text match** — dump.cs is C# text; the matcher hits raw bytes/lines, not parsed symbol names. v1 accepts text matches; a structured dump.cs symbol parser is deferred.
- **First-hit only** — one finding per pattern (presence). Match counts / all-locations are a deferred enhancement.
- **Policy** — networked Play fetch + auto-dump cross the roadmap's offline-first / opt-in defaults; both are gated (`--no-network`, `--no-dump`) and stay within "inspect apps you own/are authorized." Surface this in `--help` and docs.
```
