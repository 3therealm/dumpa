"""Phase 5/6 ad-enrichment: mediation graph, AD_ID merge attribution, SDK data-use."""

from __future__ import annotations

from pathlib import Path

from dumpa.core.privacy import attribute_ad_id, permission_findings
from dumpa.core.report import (
    AppFacts,
    Confidence,
    Finding,
    FindingState,
    Report,
    mediation_graph,
    render_html,
    render_markdown,
    tracker_data_use,
)
from dumpa.core.workspace import Workspace
from dumpa.scanners import mediation as mediation_scanner


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


def _tracker(subject: str, category: str, owner: str = "") -> Finding:
    attrs = {"category": category}
    if owner:
        attrs["owner"] = owner
    return Finding(kind="tracker", subject=subject, confidence=Confidence.HIGH,
                   state=FindingState.PRESENT, attributes=attrs)


def _report(findings: list[Finding]) -> Report:
    return Report(
        dumpa_version="0", created="2026-01-01T00:00:00+00:00", input_path="app.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1 << 20),
        findings=findings,
    )


# --- mediation graph ---------------------------------------------------------

def test_mediation_scan_emits_edges(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "classes.dex").write_bytes(
        b"junk com/applovin/mediation/adapters/VungleMediationAdapter junk")
    findings = mediation_scanner.scan(ws)
    assert any(f.kind == "mediation-adapter"
               and f.attributes["mediator"] == "AppLovin MAX"
               and f.attributes["network"] == "Vungle / Liftoff" for f in findings)


def test_mediation_graph_confirmed_edges() -> None:
    findings = [
        _tracker("AppLovin MAX", "ad mediation", "AppLovin"),
        Finding(kind="mediation-adapter", subject="AppLovin MAX -> Vungle / Liftoff adapter",
                confidence=Confidence.HIGH, state=FindingState.PRESENT,
                attributes={"mediator": "AppLovin MAX", "network": "Vungle / Liftoff"}),
        _tracker("Mintegral", "ads"),
    ]
    graph = mediation_graph(_report(findings))
    node = graph["AppLovin MAX"]
    assert [e.network for e in node.edges] == ["Vungle / Liftoff"]
    assert node.edges[0].confirmed is True
    # confirmed branch does NOT add co-present Mintegral as a guess
    assert all(e.network != "Mintegral" for e in node.edges)


def test_mediation_graph_copresence_fallback() -> None:
    # mediator present, no adapter classes -> co-present ad networks are inferred edges
    findings = [
        _tracker("Unity LevelPlay / ironSource", "ad mediation", "Unity"),
        _tracker("Vungle / Liftoff", "ads"),
        _tracker("Chartboost", "ads"),
    ]
    graph = mediation_graph(_report(findings))
    node = graph["Unity LevelPlay / ironSource"]
    nets = {e.network for e in node.edges}
    assert nets == {"Vungle / Liftoff", "Chartboost"}
    assert all(e.confirmed is False for e in node.edges)
    # the mediator never lists itself as one of its networks
    assert "Unity LevelPlay / ironSource" not in nets


def test_mediation_graph_empty_without_mediators() -> None:
    assert mediation_graph(_report([_tracker("Mintegral", "ads")])) == {}


# --- AD_ID merge attribution -------------------------------------------------

def test_attribute_ad_id_names_known_source() -> None:
    findings = permission_findings(["com.google.android.gms.permission.AD_ID"])
    findings.append(_tracker("Google AdMob / Mobile Ads", "ads", "Google"))
    out = attribute_ad_id(findings)
    assert len(out) == 1
    assert out[0].kind == "ad-id-attribution"
    assert out[0].confidence is Confidence.MEDIUM
    assert "Google AdMob / Mobile Ads" in out[0].attributes["source"]


def test_attribute_ad_id_unknown_source() -> None:
    findings = permission_findings(["com.google.android.gms.permission.AD_ID"])
    out = attribute_ad_id(findings)
    assert len(out) == 1
    assert "unknown" in out[0].attributes["source"]


def test_attribute_ad_id_absent() -> None:
    findings = permission_findings(["android.permission.CAMERA"])
    assert attribute_ad_id(findings) == []


# --- SDK data-use mapping ----------------------------------------------------

def test_tracker_data_use_category_default() -> None:
    assert tracker_data_use(_tracker("X", "analytics")) == "app activity, device IDs"


def test_tracker_data_use_explicit_override() -> None:
    f = Finding(kind="tracker", subject="X", confidence=Confidence.HIGH,
                state=FindingState.PRESENT,
                attributes={"category": "analytics", "data_use": "custom thing"})
    assert tracker_data_use(f) == "custom thing"


def test_tracker_data_use_unknown_category_blank() -> None:
    assert tracker_data_use(_tracker("X", "totally-unknown")) == ""


# --- renderers tolerate the new finding kinds --------------------------------

def test_renderers_include_new_sections() -> None:
    findings = [
        _tracker("AppLovin MAX", "ad mediation", "AppLovin"),
        Finding(kind="mediation-adapter", subject="AppLovin MAX -> Vungle / Liftoff adapter",
                confidence=Confidence.HIGH, state=FindingState.PRESENT,
                attributes={"mediator": "AppLovin MAX", "network": "Vungle / Liftoff"}),
        *permission_findings(["com.google.android.gms.permission.AD_ID"]),
    ]
    findings += attribute_ad_id(findings)
    report = _report(findings)
    md = render_markdown(report)
    assert "## Ad mediation" in md
    assert "AppLovin MAX → Vungle / Liftoff" in md
    assert "AD_ID likely added by" in md
    html = render_html(report)
    assert "Ad mediation" in html
    assert "AD_ID likely added by" in html
