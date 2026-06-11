"""Content-hash caching of per-scanner findings.

Each scanner's output is memoized in `<workspace>/cache/scanners/<name>.json` under a
content-hash key. The key folds together everything that can change a scanner's output:

    key = sha256( input_sha256 + dumpa_version + sorted(bundle_name:bundle_version) )

A re-run that produces the same key reuses the cached findings instead of re-scanning
the extracted tree; any drift (different input, a dumpa upgrade, an edited rule bundle)
changes the key, misses, and recomputes. The cache only decides *whether* to recompute —
findings reload byte-identically via `Finding.to_dict`/`from_dict`, so a hit equals a
cold run. A corrupt, schema-stale, or key-mismatched file is treated as a miss, never an
error (mirrors `Workspace.read_meta`).

Bundle-less scanners (native, endpoint) pass an empty bundle map and key on input +
dumpa version alone; their code is their rule source, so it rides the dumpa version.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from dumpa import __version__
from dumpa.core.report import Finding
from dumpa.core.workspace import Workspace

const_dir_cache_scanners = "scanners"
const_cache_schema = 1


def compute_scanner_key(input_sha256: str, bundle_versions: dict[str, str],
                        tool_versions: dict[str, str] | None = None) -> str:
    """Content-hash key for one scanner: input + dumpa + bundle versions + tool versions.

    `tool_versions` keys the cache on the resolved version of any external tool a scanner
    invokes (e.g. radare2), so a tool upgrade misses the cache instead of serving stale
    output. Omitted/empty reproduces the bundle-only key (back-compat).
    """
    parts = [input_sha256, __version__]
    parts.extend(f"{name}:{bundle_versions[name]}" for name in sorted(bundle_versions))
    resolved_tool_versions = tool_versions or {}
    parts.extend(f"tool:{name}:{resolved_tool_versions[name]}"
                 for name in sorted(resolved_tool_versions))
    return hashlib.sha256("\x00".join(parts).encode("UTF-8")).hexdigest()


def _scanner_path(ws: Workspace, name: str) -> Path:
    return ws.cache_dir / const_dir_cache_scanners / f"{name}.json"


def read_scanner_cache(ws: Workspace, name: str, key: str) -> list[Finding] | None:
    """Cached findings when the file exists and its key + schema match; else None (miss)."""
    path = _scanner_path(ws, name)
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="UTF-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(loaded, dict):
        return None
    data = cast("dict[str, Any]", loaded)
    if data.get("schema") != const_cache_schema or data.get("key") != key:
        return None
    raw = data.get("findings")
    if not isinstance(raw, list):
        return None
    try:
        return [Finding.from_dict(f) for f in raw]
    except (KeyError, TypeError, ValueError):
        return None


def write_scanner_cache(ws: Workspace, name: str, key: str, findings: list[Finding]) -> None:
    """Persist a scanner's findings under its content-hash key."""
    path = _scanner_path(ws, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": const_cache_schema,
        "key": key,
        "findings": [f.to_dict() for f in findings],
    }
    with path.open("w", encoding="UTF-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
