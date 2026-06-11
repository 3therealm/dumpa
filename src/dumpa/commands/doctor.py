"""`dumpa doctor` — validate external-tool availability and report versions.

`--full` adds advisory environment checks (Python/Java runtime, Android SDK paths,
signing-config readiness, rule-bundle inventory, signature-DB versions). Those checks
never affect the exit code: only a missing *required external tool* fails doctor, since
the environment checks are not required to run static analysis.
"""

from __future__ import annotations

import logging
import os
import platform
from dataclasses import dataclass
from pathlib import Path

from dumpa.core import unityasset
from dumpa.core.config import Config, load_config
from dumpa.core.errors import ConfigError, ToolExecutionError, ToolTimeoutError
from dumpa.core.process import run
from dumpa.core.rules import builtin_bundle_names, load_builtin
from dumpa.core.tools import ProbeResult, ToolRegistry, build_default_registry, resolve_executable

logger = logging.getLogger("dumpa")


@dataclass(frozen=True)
class EnvCheck:
    """One advisory environment check for `doctor --full`."""
    name: str
    status: str        # "ok" | "warn" | "info"
    detail: str


_STATUS_MARK = {"ok": "+", "warn": "~", "info": "i"}


def doctor(full: bool = False) -> None:
    """Probe every known external tool; report status and exit non-zero if a required one is missing."""
    config = load_config()
    registry = build_default_registry(config.tool_paths)
    results = registry.probe_all()
    name_width = max(len(r.spec.name) for r in results)

    missing_required: list[ProbeResult] = []
    for r in results:
        if r.found:
            mark, status = "+", "ok"
        elif r.spec.required:
            mark, status = "x", "MISSING (required)"
            missing_required.append(r)
        else:
            mark, status = "-", "missing (optional)"

        version = f"  v={r.version}" if r.version else ""
        path = f"  [{r.argv_prefix[0]}]" if r.argv_prefix else ""
        print(f"[{mark}] {r.spec.name.ljust(name_width)}  {status}{version}{path}")
        if not r.found and r.spec.install_hint:
            print(f"      hint: {r.spec.install_hint}")

    if full:
        checks = _full_checks(config, registry)
        width = max(len(c.name) for c in checks)
        print("")
        print("--- environment (advisory) ---")
        for c in checks:
            mark = _STATUS_MARK.get(c.status, "i")
            print(f"[{mark}] {c.name.ljust(width)}  {c.detail}")

    print("")
    if missing_required:
        print(f"{len(missing_required)} required tool(s) missing.")
        raise SystemExit(1)
    print("all required tools present.")


def _full_checks(config: Config, registry: ToolRegistry) -> list[EnvCheck]:
    """Build the advisory environment checks for `doctor --full` (no side effects)."""
    return [
        _check_python(),
        _check_java(),
        _check_android_sdk(),
        _check_signing(config),
        _check_rule_bundles(),
        _check_signature_db(),
        _check_unitypy(),
    ]


def _check_python() -> EnvCheck:
    return EnvCheck("python runtime", "info", platform.python_version())


def _check_java() -> EnvCheck:
    prefix = resolve_executable("java")
    if prefix is None:
        return EnvCheck("java runtime", "warn", "not found on PATH (needed by apktool/keytool)")
    try:
        proc = run([*prefix, "-version"], timeout=15, capture_stdout=True, capture_stderr=True)
    except (ToolExecutionError, ToolTimeoutError):
        return EnvCheck("java runtime", "ok", prefix[0])
    # java prints its version banner to stderr
    banner = (proc.stderr or proc.stdout or "").splitlines()
    first = next((line.strip() for line in banner if line.strip()), "")
    return EnvCheck("java runtime", "ok", first or prefix[0])


def _check_android_sdk() -> EnvCheck:
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(var, "").strip()
        if value and Path(value).is_dir():
            return EnvCheck("android sdk", "ok", f"{var}={value}")
        if value:
            return EnvCheck("android sdk", "warn", f"{var}={value} (not a directory)")
    return EnvCheck("android sdk", "warn", "ANDROID_HOME/ANDROID_SDK_ROOT not set")


def _check_signing(config: Config) -> EnvCheck:
    if config.signing is not None:
        return EnvCheck("signing config", "info",
                        f"custom keystore configured ({config.signing.keystore_file})")
    android = Path.home() / ".android" / "debug.keystore"
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    managed_base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    managed = managed_base / "dumpa" / "debug.keystore"
    if android.is_file():
        return EnvCheck("signing config", "info", f"debug keystore: {android}")
    if managed.is_file():
        return EnvCheck("signing config", "info", f"managed debug keystore: {managed}")
    return EnvCheck("signing config", "info",
                    "unsigned (no keystore; --signing debug generates one on demand)")


def _check_rule_bundles() -> EnvCheck:
    names = builtin_bundle_names()
    if not names:
        return EnvCheck("rule bundles", "warn", "none found")
    return EnvCheck("rule bundles", "info", f"{len(names)}: {', '.join(names)}")


def _check_signature_db() -> EnvCheck:
    versions: list[str] = []
    for name in builtin_bundle_names():
        try:
            versions.append(f"{name}={load_builtin(name).version}")
        except ConfigError:
            versions.append(f"{name}=?")
    if not versions:
        return EnvCheck("signature db", "warn", "no bundles")
    return EnvCheck("signature db", "info", ", ".join(versions))


def _check_unitypy() -> EnvCheck:
    """UnityPy powers Unity serialized-asset parsing; optional (pip install dumpa[unity])."""
    if not unityasset.available():
        return EnvCheck("unitypy", "info", "not installed (Unity asset parsing disabled; "
                        "pip install dumpa[unity])")
    return EnvCheck("unitypy", "info", unityasset.unitypy_version() or "installed")
