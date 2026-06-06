"""Permission capability mapping + the privacy data-access bundle/scanner."""

from __future__ import annotations

from pathlib import Path

from dumpa.core.privacy import permission_findings
from dumpa.core.report import Confidence, FindingState
from dumpa.core.rules import load_builtin
from dumpa.core.workspace import Workspace
from dumpa.scanners import privacy as privacy_scanner


def test_permission_findings_maps_known() -> None:
    fs = permission_findings([
        "android.permission.ACCESS_FINE_LOCATION",
        "com.google.android.gms.permission.AD_ID",
        "android.permission.NOT_A_REAL_PERMISSION",
    ])
    assert len(fs) == 2  # unknown permission ignored
    subjects = {f.subject for f in fs}
    assert {"Precise location", "Advertising ID (AD_ID)"} <= subjects
    categories = {f.attributes["category"] for f in fs}
    assert {"location", "advertising id"} <= categories
    loc = next(f for f in fs if f.subject == "Precise location")
    assert loc.kind == "capability"
    assert loc.confidence is Confidence.HIGH
    assert loc.state is FindingState.PRESENT
    assert loc.attributes["permission"] == "android.permission.ACCESS_FINE_LOCATION"


def test_permission_findings_empty() -> None:
    assert permission_findings([]) == []


def test_privacy_bundle_loads() -> None:
    bundle = load_builtin("privacy")
    assert bundle.name == "privacy"
    assert len(bundle.rules) >= 5
    assert all(r.is_content for r in bundle.rules)


def test_privacy_scan_detects_ad_id_api(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    (ws.extracted_dir / "classes.dex").write_bytes(
        b"junk Lcom/google/android/gms/ads/identifier/AdvertisingIdClient; junk")
    findings = privacy_scanner.scan(ws)
    adid = next((f for f in findings if f.subject == "Advertising ID API"), None)
    assert adid is not None
    assert adid.kind == "data-access"
    assert adid.state is FindingState.REFERENCED
    assert adid.attributes["category"] == "advertising id"


def test_privacy_scan_clean(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    (ws.extracted_dir / "classes.dex").write_bytes(b"no sensitive apis here")
    assert privacy_scanner.scan(ws) == []
