"""Standalone evidence-bundle writer."""

from __future__ import annotations

import json
from pathlib import Path

from dumpa.core.evidence_bundle import write_evidence_bundle
from dumpa.core.report import (
    AppFacts,
    Confidence,
    Evidence,
    Finding,
    Location,
    Report,
)


def _report(*findings: Finding) -> Report:
    return Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024, package="com.example"),
        findings=list(findings),
    )


def test_bundle_writes_manifest_index_and_snippets(tmp_path: Path) -> None:
    with_snippet = Finding(
        kind="tracker", subject="AdMob", confidence=Confidence.HIGH,
        evidence=[Evidence(description="matched class", snippet="com/google/admob",
                           tool="tracker", rule_version="2026.06.1")],
        locations=[Location(file_path="classes.dex", file_offset=42)],
    )
    no_snippet = Finding(kind="protection", subject="DexGuard", confidence=Confidence.MEDIUM)
    dest = tmp_path / "evidence"
    write_evidence_bundle(_report(with_snippet, no_snippet), dest)

    manifest = json.loads((dest / "manifest.json").read_text(encoding="UTF-8"))
    assert manifest["input_sha256"] == "a" * 64
    assert len(manifest["findings"]) == 2
    tracker = next(f for f in manifest["findings"] if f["subject"] == "AdMob")
    assert tracker["snippet_file"] == "snippets/0001__tracker__admob.txt"
    protection = next(f for f in manifest["findings"] if f["subject"] == "DexGuard")
    assert "snippet_file" not in protection  # no snippet -> no file referenced

    snippet = (dest / tracker["snippet_file"]).read_text(encoding="UTF-8")
    assert "matched class" in snippet
    assert "com/google/admob" in snippet
    # only the finding with a snippet gets a file written.
    assert sorted(p.name for p in (dest / "snippets").iterdir()) == [
        "0001__tracker__admob.txt"]

    index = (dest / "index.md").read_text(encoding="UTF-8")
    assert "`AdMob`" in index
    assert "tool=tracker" in index
    assert "classes.dex" in index
    assert "([snippet](snippets/0001__tracker__admob.txt))" in index


def test_bundle_empty_report(tmp_path: Path) -> None:
    dest = tmp_path / "evidence"
    write_evidence_bundle(_report(), dest)
    assert (dest / "manifest.json").is_file()
    assert (dest / "index.md").is_file()
    assert list((dest / "snippets").iterdir()) == []
