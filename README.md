# dumpa

A Unity/Android reverse-engineering toolkit. What began as an `.xapk` → `.apk`
converter is now a static-analysis suite: it unpacks Android apps, fingerprints
the game engine, dumps il2cpp metadata, extracts engine assets, inventories
trackers and protections, and emits blocklists and evidence bundles — all from
zero-dependency stdlib parsers, with heavyweight backends kept behind optional
extras.

> **Note:** this started as a modernized fork of
> [LuigiVampa92/xapk-to-apk](https://github.com/LuigiVampa92/xapk-to-apk)
> (the `convert` pipeline) and grew into the `dumpa` toolkit — Typer CLI,
> layered config, and a stack of analyzers. See [Acknowledgements](#acknowledgements).

## Commands

Run `dumpa --help` (or `dumpa <command> --help`) for the full surface. Today:

| Command | What it does |
|---------|--------------|
| `convert` | Merge a split `.xapk`/`.apks` bundle into one installable `.apk`. |
| `unpack` | Extract an apk/xapk/apks into a reusable workspace (`--decode` for the smali tree). |
| `repack` | Rebuild an apk from a decoded smali workspace. |
| `rewrite` | Preview/apply rule-driven smali patches, optionally rebuild + re-sign. |
| `analyze` | Full static pipeline: engine detect, il2cpp dump, scanners, report. |
| `decompile` | JADX decompile — one class (cheap) or the whole apk (`--all`). |
| `dump-il2cpp` | Dump il2cpp metadata (C# stubs, headers, scripts) from a Unity apk. |
| `scan-native` | Native (`.so`) analysis; `--tool radare2` adds entropy regions + functions. |
| `scan-trackers` | Ad/analytics tracker inventory. |
| `scan-protections` | Packer / protector / obfuscator / anti-debug fingerprinting. |
| `info` | Quick package/version/manifest inspect. |
| `export` | Render a report: `json`, `md`, `html`, `csv`, or blocklists (`hosts`, `adguard`, `nextdns`, `rethinkdns`, `trackercontrol`). |
| `evidence` | Write a self-contained evidence bundle of the findings. |
| `diff` | Compare two apks/workspaces. |
| `xref` | Build a cross-layer reference index (dex ↔ native ↔ dump.cs ↔ manifest). |
| `load` | Summarize a directory of apks. |
| `clean` | Remove a workspace. |
| `rules` | `test` / `explain` / `list` the detection rule bundles. |
| `update-signatures` | Refresh the vendored tracker/protection signature bundles. |
| `doctor` | Check that the external tools dumpa shells out to are installed. |

## Engine deep-helpers

When `analyze` recognizes the engine, it goes past "this is X" and extracts:

- **Unity** — scripting backend (IL2CPP vs Mono), IL2CPP metadata version, auto `dump.cs`, and `.assets`/AssetBundle string extraction (UnityPy extra).
- **Cocos2d-x** — JS/Lua runtime, version, and XXTEA-decryption of `*.jsc`/`*.luac` bundles when the key is recoverable.
- **Godot** — PCK discovery (standalone or appended to `libgodot*.so`), inventory, and resource extraction (Godot 4 v2/encrypted packs are detected and deferred).
- **Unreal** — UE4 `.pak` + UE5 IoStore (`.utoc`/`.ucas`) inventory and the harvestable-subset extraction (AES/LZ4 via the `unreal` extra; Oodle stays deferred).

## Requirements

- **Python ≥ 3.14**.
- One required Python dependency: [`typer`](https://typer.tiangolo.com/) (installed automatically).

### Optional extras

| Extra | Install | Adds |
|-------|---------|------|
| `unity` | `pip install dumpa[unity]` | [`UnityPy`](https://github.com/K0lb3/UnityPy) — Unity serialized-asset (`.assets`/AssetBundle) string extraction. |
| `unreal` | `pip install dumpa[unreal]` | `cryptography` + `lz4` — AES-256 / LZ4 decryption for Unreal pak/IoStore. |

Without an extra, the matching analysis is skipped (or detect-and-deferred); everything else still runs.

### External tools

On your `$PATH` (run `dumpa doctor` to check). Apache-licensed stdlib parsers do the
structural work; these tools cover the jobs that need a real toolchain:

| Tool | Needed for | Notes |
|------|------------|-------|
| [`apktool`](https://apktool.org) | `convert`, `unpack --decode`, `repack` | install via `apt`/`brew` or GitHub |
| `zipalign` | `convert` (required) | Android SDK build-tools |
| `apksigner` | signing | Android SDK build-tools |
| `aapt2` / `aapt` | output validation (optional) | Android SDK build-tools |
| `keytool` | keystore preflight (optional) | part of the JDK |
| [JADX](https://github.com/skylot/jadx) | `decompile`, `analyze --jadx` | Java/Kotlin decompiler (optional) |
| [radare2](https://github.com/radareorg/radare2) | `scan-native --tool radare2` | deeper native region scan (optional) |
| [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) / [Il2CppInspector](https://github.com/djkaty/Il2CppInspector) | `dump-il2cpp` | .NET programs; expose on PATH or via `[tools]` config |

`zipalign`, `apksigner`, and `aapt` ship in the Android SDK build-tools (install via
`sdkmanager` or Android Studio). Add the build-tools directory to your `$PATH`.

## Install

```bash
git clone https://github.com/3therealm/xapk-to-apk
cd xapk-to-apk
pip install .        # or: uv pip install .   (use -e for an editable dev install)
# with extras:
pip install '.[unity,unreal]'
```

This installs the `dumpa` console script.

## Usage

```bash
dumpa convert application.xapk          # split bundle -> application.apk (cwd)
dumpa analyze app.apk                   # full static pipeline into ./app-workspace
dumpa dump-il2cpp app.apk --engine inspector --arch arm64-v8a --out ./dump
dumpa export ./app-workspace --format hosts --out blocklist.txt
dumpa scan-trackers app.apk
dumpa diff old.apk new.apk
dumpa doctor                            # check external tools
```

`analyze` reuses a workspace across runs; pass `--no-cache` to re-run scanners,
`--jadx`/`--xref`/`--r2` to opt into the heavy passes, `--no-network` to disable
the Play-store genre lookup.

### Debug logging

```bash
dumpa --debug convert application.xapk
```

`--debug` raises logging to DEBUG and prints full tracebacks.

## Signing the result apk

Repacking a split bundle into a universal apk rewrites the manifest, which breaks
the original signature — the app must be re-signed before it will install on a
device. Signing is **off by default**; the output is left unsigned unless you
configure a keystore.

Signing activates when a keystore, alias, and **both** passwords are present
(a partial configuration is an error). Passwords are read from the environment
**only** — never from the config file — and are passed to `apksigner` via its
`env:` form, so they never appear on the process command line.

| Variable | Required | Description |
|----------|----------|-------------|
| `DUMPA_KEYSTORE_FILE` | yes | Path to your keystore file (`~` is expanded) |
| `DUMPA_KEY_ALIAS` | yes | Key alias inside the keystore |
| `DUMPA_KEYSTORE_PASSWORD` | yes | Keystore password |
| `DUMPA_KEY_PASSWORD` | yes | Key password for the alias |
| `DUMPA_MIN_SDK_VERSION` | no | Pin `--min-sdk-version` passed to `apksigner` |

The keystore path, alias, and min-sdk may also be set in `dumpa.toml` (see below);
the environment overrides file values. Passwords are env-only.

Example using the default Android SDK debug keystore on Linux:

```bash
export DUMPA_KEYSTORE_FILE=$HOME/.android/debug.keystore
export DUMPA_KEYSTORE_PASSWORD=android
export DUMPA_KEY_ALIAS=androiddebugkey
export DUMPA_KEY_PASSWORD=android
dumpa convert application.xapk
```

After signing, `dumpa` runs `apksigner verify` and requires both APK Signature
Scheme v2 and v3 to validate, printing the signer's SHA-256 fingerprint on success.
If `keytool` is on `$PATH`, a pre-flight check validates the keystore/alias/password
before unpacking and warns if the certificate expires within 90 days.

## Configuration file

Optional. `dumpa` runs on built-in defaults with no config file. Copy the example
and edit:

```bash
cp dumpa.toml.example dumpa.toml
```

Lookup order (first match wins): `$DUMPA_CONFIG` → `./dumpa.toml` →
`$XDG_CONFIG_HOME/dumpa/config.toml` (i.e. `~/.config/dumpa/config.toml`).
Environment variables override file values.

Only `[signing]`, `[tools]` (per-tool path overrides), and `[il2cpp]` (default
engine) are read from the file. See `dumpa.toml.example` for the full annotated
template.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DUMPA_CONFIG` | — | Path to the config file (see lookup order) |
| `DUMPA_IL2CPP_ENGINE` | `dumper` | il2cpp engine: `dumper` or `inspector` |
| `DUMPA_UNPACK_WORKERS` | `min(cpu, splits, 4)` | Concurrent `apktool d` invocations; `1` for serial |
| `DUMPA_JVM_HEAP` | `2048m` | `-Xmx` for every `apktool` JVM |
| `DUMPA_TOOL_TIMEOUT_SECONDS` | `1800` | Per external-tool timeout |
| `DUMPA_VALIDATION_TIMEOUT_SECONDS` | `300` | Timeout for verify/badging/keystore probes |
| `DUMPA_MAX_ZIP_ENTRIES` | `10000` | Zip-bomb guard: max archive entries |
| `DUMPA_MAX_ZIP_UNCOMPRESSED_BYTES` | `8 GiB` | Zip-bomb guard: max total uncompressed bytes |
| `DUMPA_KEEP_TMP` | — | Set to `1` to retain the `.dumpa.*` working dir |
| `DUMPA_PROFILE` | — | Run conversion under `cProfile`; `=<path>` sets the output file, `=1` writes `.dumpa-profile.prof` |

## Output validation

After build, `dumpa convert` prints a one-line `[*] result:` summary and runs
integrity checks: zip CRC scan, mandatory entry presence
(`AndroidManifest.xml`, `classes*.dex`), `zipalign` re-verify, `aapt dump badging`
package match (when `aapt2`/`aapt` is on `$PATH`), and an output-vs-input size
sanity check. Any problem is logged as a warning after the result line.

## Acknowledgements

dumpa stands on a lot of other people's work. Credit where it's due:

**Code & projects this is built on**

- **[LuigiVampa92/xapk-to-apk](https://github.com/LuigiVampa92/xapk-to-apk)** — the original xapk→apk converter this project forked from; the `convert` pipeline descends from it.
- **[Il2CppDumper](https://github.com/Perfare/Il2CppDumper)** (Perfare) and **[Il2CppInspector](https://github.com/djkaty/Il2CppInspector)** (djkaty) — the il2cpp dumping engines `dump-il2cpp` drives.
- **[UnityPy](https://github.com/K0lb3/UnityPy)** (K0lb3) — Unity serialized-asset parsing behind the `unity` extra.
- **[apktool](https://apktool.org)**, **[JADX](https://github.com/skylot/jadx)** (skylot), **[radare2](https://github.com/radareorg/radare2)**, and the Android SDK build-tools (`zipalign`/`apksigner`/`aapt2`) — the external toolchain dumpa orchestrates.
- **cocos2d-x** / Ma Bingyao's [`xxtea`](https://github.com/xxtea/xxtea-c) — the XXTEA variant the Cocos script-bundle decryptor reimplements (little-endian, length-suffixed).

**Signature & rule data (vendored, periodically refreshed via `update-signatures`)**

- **[Exodus Privacy](https://exodus-privacy.eu.org)** — the tracker signature database (AGPL-3.0 project). `trackers_exodus` bundle.
- **[TrackerControl](https://trackercontrol.org)** ([tracker-control-android](https://github.com/TrackerControl/tracker-control-android), GPL-3.0) — the host/attribution tracker blocklist, itself built from the Disconnect list and the DuckDuckGo Tracker Radar. `trackers_trackercontrol` bundle.
- **[APKiD](https://github.com/rednaga/APKiD)** (rednaga, dual GPL-3.0 / commercial) — the packer/protector/obfuscator fingerprints; dumpa lowers the usable subset of its YARA rules onto its own matchers. `protections_apkid` bundle.
- **DumpExplorer / IL2CPP Explorer** — the `dump.cs` interest-pattern rules (`general`, `match3`, `rpg`, `strategy`) are ported from its pattern sets.

**Networked enrichments**

- **[ip-api.com](https://ip-api.com)** — ASN/country lookup for observed hosts (opt-in).
- **Google Play** — the data-safety disclosure and genre lookups (opt-in; `--no-network` disables them).

The vendored bundles carry their upstreams' licenses; the relevant notices live
inside each bundle file under `src/dumpa/rules/`.

## License

dumpa is licensed under the **Apache License, Version 2.0** — see [`LICENSE.md`](LICENSE.md).
Third-party signature data and tools retain their own licenses (noted above).
