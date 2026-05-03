# XapkToApk

A simple standalone Python script with no extra library dependencies that converts the `.xapk` file into a normal `.apk` file.

## Note
This is a modernized and actively maintained fork of **[LuigiVampa92/xapk-to-apk]**(https://github.com/LuigiVampa92/xapk-to-apk). The original project appeared unmaintained and I needed something that I could call from the command line and not a browser, so this repository includes recent updates, and bug fixes.

### Usage

The usage is very simple.

First, clone the repo and make sure the script has execution permission:
```
git clone https://github.com/LuigiVampa92/xapk-to-apk
cd xapk-to-apk
chmod +x xapktoapk.py
```

Get your .xapk file ready, put it near the script, and execute the script: 
```
python xapktoapk.py application.xapk
```

You can put the symlink to this script into the path. Like this (the absolute path to the script depends on your OS and home directory settings):
```
ln -s /home/username/github/xapk-to-apk/xapktoapk.py /usr/local/bin/xapktoapk
``` 
After that, the script can be executed from any directory, like this:
```
xapktoapk application.xapk
```
The result apk file `application.apk` will be placed next to your xapk file, in the same directory.

### Requirements

Requires **Python 3.7+** (uses `dataclasses` and `from __future__ import annotations`). No third-party Python dependencies.

You **MUST** have some tools installed in your OS, and paths to their executable **MUST** be set to the `$PATH` environment variable. The script relies on that.

These tools are [apktool](https://github.com/iBotPeaches/Apktool), [zipalign](https://developer.android.com/tools/zipalign) and [apksigner](https://developer.android.com/tools/apksigner).

`apktool` can be installed via your OS package manager: `apt`, `brew`, whatever, or pulled directly from GitHub. `zipalign` and `apksigner` are part of the Android SDK build-tools distribution and must be installed via `sdkmanager` in Android Studio or via CLI.

Do not forget to make symlinks of these tools to the system's `$PATH` environment variable, OR add the entire build-tools directory to it.

### Signing the result apk

Since repackaging the splitted app bundle into the universal apk requires changing the original app's manifest file, the original signature will be broken, and the app must be resigned before you can install it on a real device.

Signing is configured via environment variables. When all four required variables are set, the script signs the resulting apk automatically. When none are set, signing is skipped and the apk is left unsigned.

| Variable | Required | Description |
|----------|----------|-------------|
| `XAPKTOAPK_KEYSTORE_FILE` | yes | Absolute path to your keystore file (`~` is expanded) |
| `XAPKTOAPK_KEYSTORE_PASSWORD` | yes | Keystore password |
| `XAPKTOAPK_KEY_ALIAS` | yes | Key alias inside the keystore |
| `XAPKTOAPK_KEY_PASSWORD` | yes | Key password for the alias |
| `XAPKTOAPK_MIN_SDK_VERSION` | no | Pin the `--min-sdk-version` passed to `apksigner` |

Passwords are passed to `apksigner` via its `env:` form, so they never appear on the process command line.

Example using the default Android SDK debug keystore on Linux:
```
export XAPKTOAPK_KEYSTORE_FILE=$HOME/.android/debug.keystore
export XAPKTOAPK_KEYSTORE_PASSWORD=android
export XAPKTOAPK_KEY_ALIAS=androiddebugkey
export XAPKTOAPK_KEY_PASSWORD=android
python xapktoapk.py application.xapk
```

After signing, the script runs `apksigner verify --verbose --print-certs` and requires both APK Signature Scheme v2 and v3 to validate. The signer's SHA-256 fingerprint is printed on success.

If `keytool` is available on the `$PATH`, a pre-flight check validates the keystore + alias + password before unpacking begins, and warns if the certificate expires within 90 days.

> **Breaking change**: previous versions accepted a `xapktoapk.sign.properties` file in the working or home directory. That file is no longer read; migrate to the environment variables above.
