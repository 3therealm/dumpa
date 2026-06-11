# Design: Cross-Reference Index (Phase 7)

Derived from the approved requirements (`/sc:brainstorm`). This is the design — types,
algorithm, interfaces, wiring. No implementation; signatures are spec.

## 1. Placement in the architecture

xref is **not a scanner**. Scanners are `(workspace) -> list[Finding]` detectors;
xref *consumes* findings + structural sidecars and emits a correlation artifact. It
belongs beside `core/diff.py` and `core/dumpcs_methods.py`: a pure derived-data module
with a thin read-only command, mirroring `dumpa diff`.

```
                 findings (run_all / build_report)  ─┐
 dumps/native/*.json (symbols)                       │
 dumps/dex/*  (class/method/field)                   ├─►  core/xref.build_xref ─► Xref
 dump.cs methods (core/dumpcs_methods)               │            │
 parsed manifest (core/manifest)                     │            ▼
 core/jni.decode_jni (Java_* → class)  ─────────────┘     dumps/xref.json (artifact)
                                                                  │
 commands/xref ──(dir | apk/xapk, mirror open_for_diff)──────────┘──► stdout / --json
```

New files:
- `core/jni.py`   — JNI symbol-name decoder (zero-dep, isolated, unit-tested alone)
- `core/xref.py`  — model + builder + renderers
- `commands/xref.py` — CLI
- wire into `cli.py` (one `from dumpa.commands import xref as xref_cmd` + `@app.command()`)

Artifact: `dumps/xref.json` (+ embedded provenance). No new workspace dir needed; add a
`Workspace.xref_sidecar` property → `dumps_dir / "xref.json"` (matches `gametype_sidecar`).

## 2. Data model (`core/xref.py`)

```python
class EntityType(enum.StrEnum):
    DOMAIN  = "domain"     # host
    CLASS   = "class"      # dotted FQN
    STRING  = "string"     # literal const (finding-derived only)
    SYMBOL  = "symbol"     # native symbol (raw)

class Layer(enum.StrEnum):
    MANIFEST = "manifest"
    SMALI    = "smali"     # smali/*.smali AND classesN.dex (same logical layer)
    JAVA     = "java"      # decompiled/  (index-if-present)
    NATIVE   = "native"    # lib/<abi>/*.so
    DUMPCS   = "dumpcs"    # dumps/dump.cs
    RESOURCE = "resource"  # res/, resources.arsc  (finding-derived only)
    ASSET    = "asset"     # assets/, dumps/{cocos,godot}/ extracted (finding-derived only)

@dataclass(frozen=True)
class Appearance:
    layer: Layer
    location: Location          # reuse core.report.Location verbatim

@dataclass(frozen=True)
class XrefEntity:
    type: EntityType
    key: str                    # normalized — the join key
    display: str                # original/raw spelling for humans
    appearances: tuple[Appearance, ...]
    aliases: tuple[str, ...] = ()   # e.g. a SYMBOL's JNI-decoded CLASS key
    @property
    def layers(self) -> frozenset[Layer]: ...

@dataclass(frozen=True)
class XrefProvenance:
    input_sha256: str
    built: str                  # ISO-8601 UTC (stamped by caller; no Date in core)
    layers_present: tuple[Layer, ...]
    deferred: tuple[str, ...]   # currently () — JNI + C++ demangle and resources all ship

@dataclass(frozen=True)
class Xref:
    provenance: XrefProvenance
    entities: tuple[XrefEntity, ...]   # PERSISTED set = correlations only (≥2 layers)
    # to_dict / from_dict / JSON read+write — same style as report.py
```

`key` is namespaced by type at the dict level (`(EntityType, key)`), so domain
`foo.com` never collides with class `foo.com`.

## 3. Normalization (`core/xref.py`, per-type)

| Type   | Canonical key                                            | Case       |
|--------|----------------------------------------------------------|------------|
| DOMAIN | host (endpoint scanner already lowercases)               | fold       |
| CLASS  | dotted — `Lcom/foo/Bar;`→`com.foo.Bar` (`dex._descriptor_to_dotted`); smali `/`→`.` | sensitive |
| STRING | exact literal                                            | sensitive  |
| SYMBOL | raw name                                                 | sensitive  |

`display` keeps the raw spelling; `key` is the normalized form. One helper:
`normalize(entity_type, raw) -> str`.

## 4. Entity sources (bounded keyspace)

Keyspace = **structural identifiers + finding-derived strings**, never arbitrary string
literals (that is unbounded). Concretely:

1. **Findings** — for each `Finding`, its `subject` and every `Location`:
   - `Location.domain`       → DOMAIN
   - `Location.dex_class`    → CLASS
   - `Location.manifest_entry` → CLASS (component FQN) or MANIFEST appearance
   - `subject` that is a dotted class / domain → typed accordingly
   - matched-string evidence snippet → STRING (this is the *only* STRING source)
   The `Layer` of each appearance is derived from `Location.file_path` (§6).
2. **Structural sidecars** (entities that may have *no* finding):
   - `dumps/native/*.json` → SYMBOL (exports+imports), NATIVE layer, RVA from `rva`
   - `dumps/dex/*`         → CLASS, SMALI layer
   - manifest (`core/manifest.load_manifest`) → CLASS (components), MANIFEST layer
   - dump.cs methods (`core/dumpcs_methods`) → CLASS (declaring type), DUMPCS layer
3. **JNI alias** (§5) — links a SYMBOL to a CLASS key.

Resources/assets contribute **only** via finding `Location.file_path` (decided:
finding-derived). Full resource-table enumeration is deferred to the Phase 8 parser and
recorded in `provenance.deferred`.

## 5. JNI decoder (`core/jni.py`)

```python
def decode_jni(symbol: str) -> tuple[str, str] | None:
    """`Java_com_foo_Bar_native_1m` -> ("com.foo.Bar", "native_m"), else None."""
```

Algorithm:
1. Require `Java_` prefix; strip it. (Reject `JavaCritical_`/non-JNI → None.)
2. Split off an overload signature: the first `__` separates name from the mangled arg
   signature; keep the left part, discard the signature (we only need class+method).
3. The boundary between class-path and method is the **last single `_`** in the left
   part (single = not part of an escape). Left of it = class path, right = method.
4. Unescape each side: `_1`→`_`, `_2`→`;`, `_3`→`[`, `_0XXXX`→`chr(0xXXXX)`; remaining
   single `_` in the class path → `/`.
5. Class path `/`→`.` → dotted FQN.

The CLASS join only needs the dotted class; an imperfect method parse still yields a
correct class alias, so this is low-risk. C++ Itanium `_Z` demangling is handled by
`core/cppname.py` (same contract: class reliable, member best-effort), wired alongside the
JNI decoder so a native C++ symbol also reads legibly and surfaces its qualified class as a
join alias (`::`→`.`).

## 6. Layer mapping (`file_path -> Layer`)

```python
def layer_of(file_path: str | None) -> Layer | None:
    # AndroidManifest.xml                          -> MANIFEST
    # smali*/**/*.smali OR **/classes*.dex         -> SMALI
    # decompiled/**                                -> JAVA
    # lib/<abi>/*.so                               -> NATIVE
    # dumps/dump.cs                                -> DUMPCS
    # res/** OR resources.arsc                     -> RESOURCE
    # assets/** OR dumps/cocos/** OR dumps/godot/**-> ASSET
    # else                                         -> None (skip)
```

Manifest-entry locations with no file_path map to MANIFEST directly.

## 7. Build algorithm (two-pass, streaming)

```python
def build_xref(ws: Workspace, findings: list[Finding], *, built: str) -> Xref:
```

Single-artifact build (the `dumpa xref <ws>` list path):

- **Pass 1 — tally** (`dict[(EntityType,str), set[Layer]]`): iterate every source in §4,
  emit `(key, layer)`, accumulate the layer-set. Keys are short strings; dump.cs is
  *streamed* (reuse `dumpcs_methods`), native/dex read from sidecars. Compact.
- **Pass 2 — materialize correlations**: re-iterate sources; for keys whose
  `len(layerset) >= 2`, collect the `Appearance`. JNI aliases merged here: a SYMBOL whose
  decoded CLASS key is itself multi-layer contributes a NATIVE appearance under that CLASS
  entity and records the alias.
- Persist only ≥2-layer entities to `dumps/xref.json`. Single-layer entities (the bulk —
  every lone symbol) are never stored, keeping the artifact bounded.

Memory bound: the tally (compact key→layerset) + the small correlation set. dump.cs is
streamed twice, never held whole — satisfies the streaming requirement on the 195 MB game.

### Single-entity query (the `dumpa xref <ws> <entity>` path)

```python
def query_xref(ws: Workspace, findings: list[Finding], entity: str, *,
               case_insensitive: bool = False) -> XrefEntity | None:
```

One streaming pass collecting every `Appearance` whose normalized key matches `entity`
(across all types, or fold case when asked). Answers even **single-layer** entities
without materializing the full index. `--case-insensitive` affects the *match*, never the
stored index.

## 8. CLI (`commands/xref.py`)

```
dumpa xref WORKSPACE [ENTITY]
           [--min-layers N]        # default 2; list view threshold
           [--case-insensitive]    # query match only
           [--json] [--out PATH]
```

- `WORKSPACE`: a dir → existing workspace (require `read_meta()`); an `.apk/.xapk` →
  ephemeral build, mirroring `analyze.open_for_diff` (extract once, build_report so
  sidecars exist, then build_xref). Reuse `open_for_diff` directly.
- No `ENTITY` → `build_xref`, persist `dumps/xref.json`, print correlations with
  `len(layers) >= --min-layers`.
- `ENTITY` given → `query_xref`, print every appearance grouped by layer with `Location`.
- `--json` machine output; `--out` redirects the artifact/output.

Renderers in `core/xref.py` (text + json), called by the command — same split as
`core/diff.py` (`diff_*` + `render_*`).

## 9. Caching / freshness

`dumps/xref.json` *is* the cache (mirror `gametype.json`). On a no-arg build: if the
artifact exists and `provenance.input_sha256 == ws.read_meta().input_sha256`, reuse it
unless `--no-cache`. No `core/cache.py` scanner-cache entry (xref isn't a scanner). The
sha guard alone gives reproducibility; layer-set changes only when the input changes.

## 10. `analyze` / report integration

- `analyze --xref` opt-in flag → build `dumps/xref.json` during analyze (after scanners,
  so findings + sidecars exist). Off by default (extra pass over dump.cs).
- The report gains a **compact line**, not inlined findings: `cross-layer correlations: N
  (dumps/xref.json)`. Avoids finding-spam; xref links existing findings, it doesn't add
  detections. (Implementation in `reporting.build_report` is a one-liner reading the
  artifact if present — design only.)

## 11. Test plan (TDD seams)

- `core/jni.py` — table-driven: plain, `_1`/`_2`/`_3` escapes, `_0XXXX` unicode, overload
  `__sig`, non-JNI → None. Pure, no fixtures.
- `core/xref.normalize` — per-type case rules; domain fold; descriptor→dotted.
- `core/xref.layer_of` — every branch + the None fallthrough.
- `build_xref` — in-memory `Workspace` + synthetic findings/sidecars: a domain seeded in
  native + smali + manifest surfaces as one ≥2-layer entity with three `Appearance`s; a
  `Java_*` symbol joins its dex class; single-layer entities excluded from the artifact;
  `--min-layers 3` raises the bar.
- `query_xref` — finds a single-layer entity the index omits; `--case-insensitive` folds.
- Streaming: a large synthetic dump.cs is iterated, not loaded (assert via the existing
  `dumpcs_methods` streaming path).

## 12. Acceptance (from requirements)

- `dumpa xref <ws> <domain>` → native+smali+manifest appearances, each a `Location`. ✓ §7
- `Java_*` symbol joins its dex class. ✓ §5
- `dumpa xref <ws>` lists ≥2-layer entities; `--min-layers 3` raises it. ✓ §8
- Bounded memory on the 195 MB game. ✓ §7 streaming + two-pass
- Missing layer → noted in `provenance.layers_present`, no crash. ✓ §2/§4
- Flips Phase 7 `[ ] cross-reference index` → `[x]`.
```
