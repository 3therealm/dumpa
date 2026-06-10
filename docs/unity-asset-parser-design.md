# Design — Unity Asset Parser

Closes the Phase 6 `[~]` Unity-asset endpoint gap (ROADMAP.md:514). Adds a UnityPy-backed
parser for Unity serialized assets (`.assets` family + UnityFS AssetBundles) so endpoint and
secret detection see object-typed content with real Unity locations, and TextAssets are
dumped for inspection.

## Locked decisions (from brainstorm)

| Decision | Choice |
|----------|--------|
| Decompression | **UnityPy** (bundles LZ4/LZMA) — lz4 dep dropped as moot |
| Parse depth | **Full TypeTree** (UnityPy resolves it) |
| Outputs | **endpoints + secrets + dump artifacts** (all three) |
| Dependency | Optional extra; absent → warn + skip (jadx/radare2 pattern) |

## Component map

```
pyproject.toml                     [project.optional-dependencies] unity = ["UnityPy>=1.20"]
src/dumpa/core/unityasset.py       NEW  — UnityPy adapter (the only file that imports UnityPy)
src/dumpa/scanners/unity_assets.py EXTEND — keep Addressables; add serialized-asset path
src/dumpa/scanners/__init__.py     EDIT — flip unity_assets to cacheable=False
src/dumpa/commands/doctor.py       EDIT (--full) — report UnityPy import presence (optional)
```

**Dependency isolation:** every `import UnityPy` lives in `core/unityasset.py`. The scanner
never imports UnityPy directly; it calls the adapter, which raises a sentinel
(`UnityPyUnavailable`) when the lib is absent. One choke point = one place to mock in tests
and one place the optional dep can leak.

## core/unityasset.py — adapter interface

```python
const_textasset_subdir = "unity/assets"   # under ws.dumps_dir

class UnityPyUnavailable(RuntimeError): ...        # raised when import fails

@dataclass
class ExtractedString:
    text: str
    container: str        # extracted/ rel path of the .assets/.bundle it came from
    asset_name: str       # TextAsset/MonoBehaviour m_Name
    path_id: int          # SerializedFile object path-id (stable Unity object key)
    class_name: str       # "TextAsset" | "MonoBehaviour"

@dataclass
class DumpedAsset:
    rel: str              # dumps/unity/assets/<name> rel path
    container: str
    asset_name: str
    path_id: int
    sha256: str
    size: int

def available() -> bool: ...               # importlib.util.find_spec("UnityPy") is not None
def unitypy_version() -> str | None: ...    # for the provenance sidecar

def parse_container(path, *, max_obj, max_bytes_per_obj) -> tuple[list[ExtractedString], list[bytes]]
    # load one .assets/.bundle via UnityPy.load(); iterate env.objects;
    #   TextAsset      -> read .m_Script (str|bytes); yield ExtractedString + raw bytes
    #   MonoBehaviour  -> read_typetree(); collect str-typed leaf fields (bounded)
    # bounded: stop after max_obj objects; truncate each value at max_bytes_per_obj.
    # fail-soft per object (UnityPy can throw on exotic versions) -> log + skip object.
```

Why an adapter and not raw UnityPy in the scanner: UnityPy's object model differs across
versions; concentrating the `.read()` / `read_typetree()` calls in one module means a
UnityPy API shift is a one-file fix, and the scanner stays pure dumpa types.

## scanners/unity_assets.py — control flow (extended)

```
scan(ws):
    findings = _addressables(ws)              # EXISTING — unchanged, keep as-is
    if not unityasset.available():
        warn "UnityPy not installed; skipping Unity serialized-asset parse"; return findings
    containers = _locate(ws.extracted_dir)    # globs below; [] -> return findings (no-op)
    dumped, strings = [], []
    for c in containers (bounded by _MAX_CONTAINERS, _MAX_TOTAL_BYTES):
        es, raw_texts = unityasset.parse_container(c, ...)
        strings += es
        dumped += _dump_textassets(ws, c, raw_texts, es)   # write to dumps/unity/assets/
    findings += _endpoint_findings(strings, dumped, ws)    # harvest_urls over strings+dumps
    findings += _secret_findings(ws)                       # apply_bundle("secrets", dump dir)
    findings += [_summary_finding(containers, dumped)]     # engine-detail: counts
    _write_sidecar(ws, {...})                              # .dumpa-unity-assets.json
    return findings
```

### Container location globs
```
assets/bin/Data/**           # main serialized files: level*, sharedassets*, resources.assets
**/*.assets                  # .assets / .assets.resS pairs (resS handled by UnityPy)
**/*.bundle                  # UnityFS AssetBundles
assets/**/*.unity3d          # legacy bundle extension
```
Magic sniff (`UnityFS` / raw SerializedFile header) inside the adapter; non-Unity matches
fail-soft to skip. Path-traversal / `is_relative_to(root)` guard mirrors `_catalogs()`.

### Endpoints (reuse, don't reinvent)
`_endpoint_findings` runs the existing `endpoint.harvest_urls(bytes)` over each
ExtractedString's text **and** each dumped file's bytes — identical to godot's
`_endpoint_findings`. Emits `kind="endpoint"` findings (subject = host) that flow through the
shared `enrich_domain_attribution` + `enrich_endpoint_purpose` tail automatically. Location
carries `file_path=dumps/unity/assets/<name>`, plus the Unity `asset_name`/`path_id` in
`attributes` for traceability.

### Secrets (reuse the bundle over dumped artifacts)
The always-run `secret.scan` only walks `extracted/`, so it never sees `dumps/`. Mirror the
godot precedent: `apply_bundle(load_builtin("secrets"), ws.dumps_dir / "unity/assets")` after
dumping, so analytics/ad/API-key regexes hit extracted TextAsset bodies. Findings are real
`secret`-kind findings with dump-relative locations.

### Dump artifacts + sidecar
TextAsset bodies → `dumps/unity/assets/<sanitized-name>` (collision-safe: append `__<path_id>`).
Provenance sidecar `dumps/unity/.dumpa-unity-assets.json`:
```json
{ "engine": "unity", "unitypy_version": "1.20.x", "dumpa_version": "...",
  "containers": [{"rel": "...", "objects": N, "textassets": M}],
  "dumped": [{"rel": "...", "asset_name": "...", "path_id": 123, "sha256": "...", "size": N}] }
```

## Registry change

`scanners/__init__.py`: `ScannerSpec("unity_assets", unity_assets.scan)` →
`ScannerSpec("unity_assets", unity_assets.scan, cacheable=False)`. Rationale identical to
cocos/godot: it writes artifacts to `dumps/`, so caching empty/partial output would poison a
workspace; keep it always-run until dump sidecars enter the cache key. (Addressables-only
behaviour was code-only/cacheable before — acceptable regression, the scan is cheap and
self-gates to no-op without containers.)

## Bounds (NF2 — memory/output safety)

| Constant | Purpose | Default |
|----------|---------|---------|
| `_MAX_CONTAINERS` | cap files parsed | 200 |
| `_MAX_TOTAL_BYTES` | cap aggregate input read | 1 GiB |
| `max_obj` / container | cap objects walked | 5000 |
| `max_bytes_per_obj` | truncate one TextAsset/field | 1 MiB |
| `_MAX_DUMP_FILES` / `_MAX_DUMP_TOTAL` | cap `dumps/` explosion (OQ3) | 2000 / 256 MiB |

UnityPy loads a container into memory to parse it (no streaming API), so `_MAX_TOTAL_BYTES`
and per-container size checks are the real guard — a 2 GB `.assets` is skipped + warned, not
loaded.

## Data flow

```
extracted/ .assets|.bundle ──► core/unityasset.parse_container (UnityPy)
                                   │
                    ┌──────────────┼───────────────┐
              ExtractedString   raw TextAsset bytes
                    │                  │
                    │            dumps/unity/assets/<name>  (+ sidecar)
                    │                  │
          harvest_urls(text)     harvest_urls(bytes)        apply_bundle("secrets", dumpdir)
                    └────────► endpoint findings ◄──┘              │
                                   │                          secret findings
                    enrich_domain_attribution / _purpose (shared tail)
```

## Open questions carried forward (decide at implement-time)

1. **Engine-encrypted/custom AssetBundles** — some games XOR/encrypt bundles before UnityPy
   can read them. Proposal: **defer** (warn "encrypted/unreadable bundle"), mirroring Godot-4
   encrypted-PCK. Cheap to revisit.
2. **`.resS` / StreamData external streams** — UnityPy resolves sibling `.resS` automatically
   for TextAssets; CompressedMesh/StreamData (audio/texture) are **out of scope** (no string
   value). No extra work.
3. **Dump cap policy** — `_MAX_DUMP_FILES`/`_MAX_DUMP_TOTAL` above; log when truncated (the
   roadmap's "no silent caps" rule).
4. **doctor surfacing** — add an optional `--full` line reporting UnityPy presence? Low effort,
   matches signature-DB advisory checks. Proposed: yes.

## Verification criteria (for /sc:implement → TDD)

- Adapter import-guard: `available()` False when UnityPy absent; scanner warns + still returns
  Addressables findings (no crash). *(mock find_spec)*
- `parse_container` on a fixture `.assets` with a known TextAsset URL → ExtractedString carries
  the URL, asset_name, path_id.
- End-to-end: a Unity workspace with a TextAsset holding `https://api.example.com/x` →
  `analyze` emits an `endpoint` finding for `api.example.com` with a `dumps/unity/assets/...`
  location, and the TextAsset is on disk.
- A secret-bearing TextAsset (e.g. `AIza...`) → `secret` finding from the dump dir.
- Bounds: oversized container skipped + warned, never OOM.
- `cacheable=False` honored (re-run reproduces dumps).

## Next step

`/sc:implement` against this doc (TDD per the verification criteria). Q1–Q4 resolve inline at
implement-time with the proposals above unless reconsidered.
