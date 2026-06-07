# Design: Structured Manifest Parser + Consumers

Status: design (pre-implementation). Requirements: see the `/sc:brainstorm` spec.
Decisions locked: **zero-dep AXML decoder**; full slice (**primitive + facts +
privacy audit + manifest matcher kind**).

One parser, four consumers. Dependency order:

```
core/axml.py  ──►  core/manifest.py  ──►  reporting.py (facts)
  (decoder)        (ManifestInfo +        scanners/manifest_privacy.py (audit)
                    workspace accessor)    core/rules.py  (manifest matcher kind)
                                           rules/manifest.toml (combo + audit bundle)
```

Everything below is stdlib-only (`struct`, `re`, `tomllib`). No new deps. Matches
the tomllib/zero-dep ethos.

---

## 1. `core/axml.py` — binary AXML decoder

Pure: `parse_axml(data: bytes) -> AxmlDocument`. No I/O. Little-endian throughout.
On any inconsistency raise `AxmlError(DumpaError)`; callers degrade to empty, never
crash.

### Chunk layout (what we walk)

Every chunk: `{type:u16, headerSize:u16, size:u32, ...}`.

| Chunk | type | We need |
|-------|------|---------|
| XML file header | `0x0003` | wrapper; iterate inner chunks |
| String pool | `0x0001` | `stringCount`, `flags` (UTF8 bit `0x100`), offsets, string data |
| Resource map | `0x0180` | `(size-8)/4` u32 resIDs; index→attr-name fallback |
| Start namespace | `0x0100` | prefix/uri strrefs → android ns URI |
| Start element | `0x0102` | ns, name, `attributeCount`, then attrs |
| End element | `0x0103` | pop element stack |
| CDATA | `0x0104` | (ignored for manifest) |

### String pool decoding (the fiddly part)

- header fields: `stringCount u32, styleCount u32, flags u32, stringsStart u32, stylesStart u32`.
- `flags & 0x100` (UTF8_FLAG) selects encoding.
- offsets: `stringCount` u32, each relative to `stringsStart`.
- **UTF-16** string: `u16 len` (if high bit set → `((len & 0x7fff) << 16) | next_u16`),
  then `len` UTF-16LE code units, null-terminated.
- **UTF-8** string: `u8 charLen` (high-bit 2-byte ext), `u8 byteLen` (high-bit 2-byte
  ext), then `byteLen` UTF-8 bytes, null-terminated. Decode the byte form.
- Bounds-check each offset against chunk end; out-of-range index → empty string, not a
  crash (defensive).

### Start-element attributes

Per attribute (20 bytes):
`ns u32(strref,-1), name u32(strref), rawValue u32(strref,-1), {size u16, res0 u8, dataType u8, data u32}`.

Value resolution:
- `rawValue != 0xffffffff` → `pool[rawValue]` (string).
- else by `dataType`: `0x03` STRING→`pool[data]`; `0x12` INT_BOOLEAN→`data != 0`
  (`0xffffffff`=true, `0`=false); `0x10/0x11` INT→`str(data)`; `0x01` REFERENCE→
  `"@%08x" % data` (rarely needed).

Name resolution:
- `pool[name]` is normally `"exported"`, `"name"`, … Use it.
- If empty (some compilers strip names, keep only resource IDs): fall back to
  `RESID_TO_ATTR[resmap[name]]`. Known IDs we map (only what we read):

  | attr | resId |
  |------|-------|
  | `name` | `0x01010003` |
  | `permission` | `0x01010006` |
  | `exported` | `0x01010010` |
  | `debuggable` | `0x0101000f` |
  | `allowBackup` | `0x01010280` |
  | `scheme` | `0x01010027` |
  | `host` | `0x01010028` |
  | `path` / `pathPrefix` / `pathPattern` | `0x0101002a` / `0x0101002b` / `0x0101002c` |
  | `minSdkVersion` | `0x0101020c` |
  | `targetSdkVersion` | `0x01010270` |
  | `autoVerify` | `0x010104ee` |
  | `versionCode` | `0x0101021b` |
  | `versionName` | `0x0101021c` |

  Android namespace = `http://schemas.android.com/apk/res/android`; an attr's ns strref
  resolving to that URI marks it android-namespaced.

### Output: a thin DOM

`AxmlDocument` = nested `AxmlElement{tag, attrs: dict[str,str|bool], children: tuple}`,
built with an element stack on start/end. `attrs` keys are the local attr name
(android-namespaced ones are what we care about; manifest has no name clashes across
ns for the fields we read). Defensive caps: max element count, max depth → `AxmlError`.

---

## 2. `core/manifest.py` — `ManifestInfo` + workspace accessor

Maps the generic DOM to a manifest-specific structured model.

```python
@dataclass(frozen=True)
class IntentData:
    scheme: str | None; host: str | None; path: str | None

@dataclass(frozen=True)
class IntentFilter:
    actions: tuple[str, ...]
    categories: tuple[str, ...]
    data: tuple[IntentData, ...]
    auto_verify: bool = False

@dataclass(frozen=True)
class Component:
    type: str                 # activity | activity-alias | service | receiver | provider
    name: str
    exported: bool | None     # None = attribute absent
    permission: str | None
    intent_filters: tuple[IntentFilter, ...]
    @property
    def exported_effective(self) -> bool:
        # explicit value wins; else Android's pre-S default: exported iff it has a filter
        return self.exported if self.exported is not None else bool(self.intent_filters)

@dataclass(frozen=True)
class ManifestInfo:
    package: str | None
    version_code: str | None
    version_name: str | None
    min_sdk: str | None
    target_sdk: str | None
    permissions: tuple[str, ...]
    debuggable: bool
    allow_backup: bool | None   # None = absent (defaults true pre-Android-12)
    components: tuple[Component, ...]

def parse_manifest_bytes(data: bytes) -> ManifestInfo: ...
```

### Workspace accessor (the shared primitive)

```python
@lru_cache(maxsize=8)
def _cached(path: str, size: int, mtime_ns: int) -> ManifestInfo | None: ...

def load_manifest(ws: Workspace) -> ManifestInfo | None:
    """Parse <extracted>/AndroidManifest.xml. None on absent/parse-failure (logged debug).
    Cached on (path, size, mtime) so engine.scan + privacy.scan + reporting re-use one parse."""
```

Every consumer calls `load_manifest(ws)`. Tiny file (KB); cache keeps it to one parse
per analyze even though three callers ask.

---

## 3. Facts wiring (`reporting.py`)

- Parse once: `manifest = load_manifest(ws)`.
- Field precedence **manifest → aapt badging** (keep aapt as fallback, demoted):
  package, version_name/code, min/target sdk, permissions take the manifest value when
  present, else `badging.*`.
- **ABIs stay from badging** (`lib/` native-code listing — not in the manifest).
- On `manifest is None`: warning `"manifest parse failed; facts fell back to aapt"`.
- `AppFacts` gains high-signal scalar flags (cheap, keep header lean):
  - `debuggable: bool | None`
  - `allow_backup: bool | None`
  - `exported_component_count: int | None`
  - **Full component list stays OUT of facts** — it lives in the privacy-audit findings,
    so the header doesn't bloat but every component detail is still in the report.
    *(open question: store full list in facts too? default = no.)*
- Markdown header: add `debuggable`, `allowBackup`, `exported components` rows.

---

## 4. `scanners/manifest_privacy.py` — Phase 6 audit

Pure `(ws) -> list[Finding]`. New finding `kind="manifest"`. Calls `load_manifest(ws)`;
`[]` if None. Registered in `SCANNERS` (after `engine`, before `tracker`).

| Signal | subject | confidence | attributes |
|--------|---------|-----------|------------|
| exported component (explicit `exported=true`) | `exported {type}: {name}` | high | `category=exported-component`, `guarded=yes/no` |
| exported via intent-filter (implicit) | `exported {type}: {name}` | medium | `category=exported-component`, `exported=implicit` |
| `debuggable=true` | `debuggable=true` | high | `category=debug-flag` |
| `allowBackup=true` | `allowBackup=true` | medium | `category=backup-flag` |
| boot receiver (`RECEIVE_BOOT_COMPLETED`) | `boot receiver: {name}` | medium | `category=boot-receiver` |
| install-referrer receiver (`INSTALL_REFERRER`) | `install-referrer: {name}` | medium | `category=install-referrer` |
| deep link (`http(s)` + host + BROWSABLE) | `deep link: {scheme}://{host}` | low | `category=deep-link` |

Each Finding: `state=present`, `Location(manifest_entry=name_or_entry)`, `Evidence`
(`tool="manifest"`, describing the matched element). `guarded=no` (exported + no
`permission`) is the one worth surfacing loudest.

**Suspicious permission combos are NOT here** — they are data, expressed as
`match="all"` manifest-matcher rules in `rules/manifest.toml` (§5). Keeps the scanner
free of hardcoded policy.

---

## 5. `manifest` matcher kind (`core/rules.py`)

Third rule type alongside path (`globs`) and content (`strings`/`regex`). Operates over
**parsed `ManifestInfo`**, not raw bytes — the difference that makes
package/component/permission detection precise.

### TOML shape

```toml
[[rule]]
kind = "engine"
subject = "Unity"
confidence = "high"
manifest = ["^com\\.unity3d\\."]   # regex list (exclusive with globs/strings/regex)
manifest_field = "package"          # package|permission|component|action|category|any
match = "any"                       # any (default) | all  ← "all" = AND = combos
```

### Engine changes (surgical)

- `Rule`: add `manifest: tuple[str,...] = ()`, `manifest_field: str = "any"`; property
  `is_manifest`.
- `_parse_rule`: exclusive-key set becomes `{globs, strings, regex, manifest}` (exactly
  one). Validate `manifest_field` against the allowed set; compile each regex.
- `apply_bundle(bundle, extracted_dir, manifest=None)`: **new optional 3rd param**
  (back-compat — existing callers unchanged). Lazily `load_manifest`-equivalent parse
  from `extracted_dir/AndroidManifest.xml` only if the bundle has manifest rules and
  `manifest is None`.
- `_apply_manifest_rules`: for each rule, gather candidate strings from the selected
  field (`package`→`[info.package]`; `permission`→`info.permissions`;
  `component`→component names; `action`/`category`→flattened from intent-filters;
  `any`→all of the above). Regex-search; `match="all"` requires every pattern to hit
  **at least one** candidate (this is the AND that expresses combos), `"any"` requires
  one. Finding `Location(manifest_entry=matched_value)`, evidence names field + pattern.

### Bundle integration

- `rules/manifest.toml` (new): suspicious permission combos as `match="all"`
  `manifest_field="permission"` rules (e.g. fine-location + internet; read-phone-state +
  internet; query-all-packages).
- `rules/engines.toml` (existing): add `manifest` package-prefix rules for engines whose
  package namespaces are diagnostic (Unity `com.unity3d`, Cocos `org.cocos2dx`, Godot
  `org.godotengine`, …) → flips Phase 4 "manifest entries" + "package names" `[ ]`.
- `engine.scan` / `tracker.scan` already call `apply_bundle(...)`; they pass
  `load_manifest(ws)` so the parse is shared.

---

## Data flow (one analyze)

```
analyze → build_workspace (raw zip extract: extracted/AndroidManifest.xml = binary AXML)
        → build_report
            ├─ load_manifest(ws) ─┐ (parsed once, lru-cached)
            ├─ facts  ◄───────────┤  manifest→aapt precedence
            ├─ run_all(ws)        │
            │    ├─ engine.scan ──┤  apply_bundle(engines, …, manifest)  → package rules
            │    ├─ manifest_privacy.scan ◄─┘  exported/debuggable/deep-link findings
            │    └─ tracker.scan …  apply_bundle(trackers, …, manifest)
            └─ Report(facts, findings)
```

## Test plan (all device-free, pure)

- `axml`: hand-built minimal AXML bytes (string pool + one element + bool/str attrs,
  both UTF-8 and UTF-16 pools); a stripped-name manifest exercising the resmap fallback;
  truncated/garbage → `AxmlError`.
- `manifest`: DOM → `ManifestInfo` for package, permissions, exported (explicit + None +
  implicit-via-filter), debuggable, deep-link data.
- `reporting`: manifest present → facts from manifest; manifest absent → aapt fallback +
  warning.
- `manifest_privacy`: each signal row fires; `guarded=no` distinguished.
- `rules`: `manifest_field` selection; `match="all"` combo fires only when all perms
  present; engines bundle package rule fires.
- Round-trip the new `AppFacts` scalar fields through `to_dict`/`from_dict`.

## Roadmap checkboxes this flips

Phase 1/2 structured-manifest primitive; Phase 4 engine detection *manifest entries* +
*package names*; Phase 6 *whole manifest privacy audit section*; Phase 5 tracker
*manifest component* evidence; Phase 3 *manifest matcher kind*. ~8 boxes.

## Open decisions (carry into implement)

1. **Full component list in `AppFacts`?** Default no (findings carry it). Flip if a
   consumer needs the structured list in the JSON header.
2. **Keep aapt as fallback, or drop once AXML proven?** Design keeps it (lowest risk).
3. **`dumpa manifest` standalone command?** Out of this slice; surfaced via
   analyze/info only. Add later as a thin printer over `load_manifest`.
4. **`min/target sdk` as INT references** in odd manifests → may need resmap int resolve;
   aapt fallback covers it meanwhile.
```
