"""`dumpa doctor` — validate external-tool availability and report versions."""

from __future__ import annotations

from dumpa.core.config import load_config
from dumpa.core.tools import build_default_registry


def doctor() -> None:
    """Probe every known external tool; report status and exit non-zero if a required one is missing."""
    registry = build_default_registry(load_config().tool_paths)
    results = registry.probe_all()
    name_width = max(len(r.spec.name) for r in results)

    missing_required = []
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

    print("")
    if missing_required:
        print(f"{len(missing_required)} required tool(s) missing.")
        raise SystemExit(1)
    print("all required tools present.")
