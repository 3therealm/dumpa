# dumpa

A Unity/Android reverse-engineering toolkit. Two commands today:

- **`dumpa convert`** — merge a split `.xapk` bundle into a single installable `.apk`.
- **`dumpa dump-il2cpp`** — dump il2cpp metadata (C# stubs, headers, scripts) from a Unity APK.

Plus **`dumpa doctor`** to check that the external tools it shells out to are installed.

> **Note:** this is a modernized, actively maintained fork of
> [LuigiVampa92/xapk-to-apk](https://github.com/LuigiVampa92/xapk-to-apk),
> restructured as the `dumpa` toolkit (Typer CLI, layered config, il2cpp dumping).

## Requirements

- **Python ≥ 3.14**.
- One third-party Python dependency: [`typer`](https://typer.tiangolo.com/) (installed automatically).
- External command-line tools on your `$PATH` (see below). Run `dumpa doctor` to check them.

### External tools

| Tool | Needed for | Notes |
|------|------------|-------|
| [`apktool`](https://apktool.org) | convert (required) | install via `apt`/`brew` or from GitHub |
| `zipalign` | convert (required) | Android SDK build-tools |
| `apksigner` | convert (only when signing) | Android SDK build-tools |
| `aapt2` / `aapt` | convert output validation (optional) | Android SDK build-tools |
| `keytool` | keystore preflight (optional) | part of the JDK |
| Il2CppDumper / Il2CppInspector | `dump-il2cpp` | .NET programs; expose on PATH or via `[tools]` config |

`zipalign`, `apksigner`, and `aapt` ship in the Android SDK build-tools (install via
`sdkmanager` or Android Studio). Add the build-tools directory to your `$PATH`.

## Install

```bash
git clone https://github.com/3therealm/xapk-to-apk
cd xapk-to-apk
pip install .        # or: uv pip install .   (use -e for an editable dev install)
```

This installs the `dumpa` console script.

## Usage

### Convert an xapk

```bash
dumpa convert application.xapk
```

The result `application.apk` is written to the **current working directory**.

Check your tools first if unsure:

```bash
dumpa doctor
```

### Dump il2cpp metadata

```bash
dumpa dump-il2cpp app.apk
dumpa dump-il2cpp app.apk --engine inspector --arch arm64-v8a --out ./dump
```

By default the output lands in `<apk-stem>-il2cpp` next to the APK. Choose the
engine with `--engine dumper|inspector` (default from config), pin an ABI with
`--arch`, and override the output directory with `--out`.

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
integrity checks:

- Zip CRC scan
- Mandatory entry presence (`AndroidManifest.xml`, `classes*.dex`)
- `zipalign` re-verify
- `aapt dump badging` package match (when `aapt2`/`aapt` is on `$PATH`)
- Output size sanity vs. input xapk size

Any problem is logged as a warning after the result line.
