"""`dumpa rules` — test, explain, and list rule bundles.

- `rules test` applies a bundle (built-in or a custom TOML file) to a workspace, a
  plain extracted directory, or an `.apk`, and prints the findings.
- `rules explain` shows why a subject would be detected (its matchers + provenance).
- `rules list` lists the built-in bundles with their version/source/date.
"""

from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from dumpa.core.archive import safe_extract_zip
from dumpa.core.errors import DumpaError
from dumpa.core.fs import working_tmp_dir
from dumpa.core.report import Finding
from dumpa.core.rules import (
    RuleBundle,
    apply_bundle,
    builtin_bundle_names,
    load_builtin,
    load_bundle,
)
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_default_builtin_bundle = "engines"


def _select_bundle(bundle_path: Path | None, builtin: str | None) -> RuleBundle:
    """Resolve the bundle to use: explicit file > named built-in > default 'engines'."""
    if bundle_path is not None:
        return load_bundle(bundle_path.resolve())
    return load_builtin(builtin or const_default_builtin_bundle)


@contextmanager
def _extracted_tree(target: Path) -> Generator[Path]:
    """Yield an extracted apk tree for the target (workspace dir, plain dir, or .apk)."""
    resolved = target.resolve()
    if resolved.is_dir():
        ws = Workspace(root=resolved)
        yield ws.extracted_dir if ws.extracted_dir.is_dir() else resolved
        return
    suffix = resolved.suffix.lower()
    if suffix == ".apk":
        with working_tmp_dir(resolved.parent) as tmp:
            extracted = tmp / "extracted"
            safe_extract_zip(resolved, extracted)
            yield extracted
        return
    if suffix == ".xapk":
        raise DumpaError("rules test on a .xapk: run `dumpa analyze` first, then test the workspace")
    raise DumpaError(f"unsupported target {resolved.name}: pass a workspace dir or an .apk")


def _print_findings(bundle: RuleBundle, findings: list[Finding]) -> None:
    print(f"bundle {bundle.name} v{bundle.version} ({bundle.source}) — {len(findings)} finding(s)")
    if not findings:
        print("  no matches")
        return
    for finding in findings:
        print(f"[{finding.confidence.value}] {finding.kind}: {finding.subject} ({finding.state.value})")
        for ev in finding.evidence:
            detail = f" -> {ev.snippet}" if ev.snippet else ""
            print(f"    - {ev.description}{detail}")


def rules_test(target: Path, *, bundle_path: Path | None = None, builtin: str | None = None) -> None:
    """Apply a rule bundle to a target and print the findings."""
    bundle = _select_bundle(bundle_path, builtin)
    with _extracted_tree(target) as extracted:
        findings = apply_bundle(bundle, extracted)
    _print_findings(bundle, findings)


def rules_explain(subject: str, *, bundle_path: Path | None = None, builtin: str | None = None) -> None:
    """Explain how a subject is detected: its matchers and bundle provenance."""
    bundle = _select_bundle(bundle_path, builtin)
    matches = [r for r in bundle.rules if r.subject.lower() == subject.lower()]
    if not matches:
        raise DumpaError(f"no rule with subject {subject!r} in bundle {bundle.name!r}")
    for rule in matches:
        print(f"{rule.kind}: {rule.subject}")
        print(f"  confidence: {rule.confidence.value}")
        print(f"  match:      {rule.match} (fires when {rule.match} of the globs match)")
        print(f"  bundle:     {bundle.name} v{bundle.version} ({bundle.source}, updated {bundle.updated})")
        print("  globs:")
        for glob in rule.globs:
            print(f"    - {glob}")


def rules_list() -> None:
    """List the built-in rule bundles with their provenance."""
    names = builtin_bundle_names()
    if not names:
        print("no built-in rule bundles")
        return
    for name in names:
        bundle = load_builtin(name)
        print(f"{name}: v{bundle.version}  source={bundle.source}  "
              f"updated={bundle.updated}  rules={len(bundle.rules)}")
