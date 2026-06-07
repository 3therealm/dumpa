"""Tracker scanner: manifest-component evidence + same-subject merge."""

from __future__ import annotations

from pathlib import Path

from _axml_build import build_axml

from dumpa.core.report import Confidence
from dumpa.core.workspace import Workspace
from dumpa.scanners import tracker


def _ws(tmp_path: Path, *, manifest: bytes | None = None, dex: bytes | None = None) -> Workspace:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    if manifest is not None:
        (extracted / "AndroidManifest.xml").write_bytes(manifest)
    if dex is not None:
        (extracted / "classes.dex").write_bytes(dex)
    return Workspace(root=tmp_path)


def _manifest_with(component: str) -> bytes:
    return build_axml(("manifest", {"package": "com.dev.app"}, [
        ("application", {}, [("activity", {"name": component}, [])]),
    ]))


def test_manifest_component_yields_tracker(tmp_path: Path) -> None:
    ws = _ws(tmp_path, manifest=_manifest_with("com.google.android.gms.ads.AdActivity"))
    findings = tracker.scan(ws)
    admob = [f for f in findings if f.subject == "Google AdMob / Mobile Ads"]
    assert len(admob) == 1
    assert admob[0].attributes["owner"] == "Google"
    assert admob[0].locations[0].manifest_entry == "com.google.android.gms.ads.AdActivity"


def test_dex_and_manifest_merge_into_one(tmp_path: Path) -> None:
    ws = _ws(
        tmp_path,
        manifest=_manifest_with("com.google.android.gms.ads.AdActivity"),
        dex=b"xx Lcom/google/android/gms/ads/MobileAds; yy",
    )
    findings = tracker.scan(ws)
    admob = [f for f in findings if f.subject == "Google AdMob / Mobile Ads"]
    assert len(admob) == 1                                # merged, not duplicated
    f = admob[0]
    # one finding now carries both a file-offset location and a manifest-entry location
    assert any(loc.file_offset is not None for loc in f.locations)
    assert any(loc.manifest_entry is not None for loc in f.locations)
    assert len(f.evidence) >= 2


def test_domain_detector_merges_into_class_finding(tmp_path: Path) -> None:
    # dex carries both the AppsFlyer class path (high) and the appsflyer.com domain
    # literal (low detector) -> one finding, strongest confidence, domain location kept.
    ws = _ws(tmp_path, dex=b"xx Lcom/appsflyer/AppsFlyerLib; yy appsflyer.com zz")
    findings = tracker.scan(ws)
    af = [f for f in findings if f.subject == "AppsFlyer"]
    assert len(af) == 1
    f = af[0]
    assert f.confidence is Confidence.HIGH                 # class-path wins over low detector
    assert any(loc.domain == "appsflyer.com" for loc in f.locations)


def test_engine_activity_is_not_a_tracker(tmp_path: Path) -> None:
    # com.unity3d.player.* is the engine, not the ads SDK — must not match Unity Ads.
    ws = _ws(tmp_path, manifest=_manifest_with("com.unity3d.player.UnityPlayerActivity"))
    assert [f for f in tracker.scan(ws) if f.subject == "Unity Ads"] == []
