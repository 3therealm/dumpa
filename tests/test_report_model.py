"""core.report: serialization round-trip, None-omission, markdown render."""

from __future__ import annotations

import json

from dumpa.core.report import (
    AppFacts,
    Confidence,
    Evidence,
    Finding,
    FindingState,
    Location,
    Report,
    render_markdown,
    to_json,
)


def _sample() -> Report:
    return Report(
        dumpa_version="0.1.0",
        created="2026-06-06T00:00:00+00:00",
        input_path="/abs/game.xapk",
        facts=AppFacts(
            input_sha256="a" * 64, input_size=12345, package="com.example.game",
            version_name="1.2.3", version_code="42", min_sdk="24", target_sdk="34",
            abis=["arm64-v8a"], permissions=["android.permission.INTERNET"],
            signer_cert_sha256="deadbeef", signing_schemes=["v2", "v3"],
        ),
        tool_versions={"apktool": "3.0.2"},
        findings=[
            Finding(
                kind="tracker", subject="firebase-analytics", confidence=Confidence.HIGH,
                evidence=[Evidence(description="class match", tool="dex")],
                locations=[Location(domain="firebase.googleapis.com", dex_class="com/google/X")],
            ),
        ],
        warnings=["apk is unsigned"],
    )


def test_round_trip() -> None:
    report = _sample()
    restored = Report.from_dict(report.to_dict())
    assert restored == report


def test_json_round_trip() -> None:
    report = _sample()
    restored = Report.from_dict(json.loads(to_json(report)))
    assert restored == report


def test_finding_state_default_is_present() -> None:
    f = Finding(kind="engine", subject="Unity", confidence=Confidence.HIGH)
    assert f.state is FindingState.PRESENT
    assert f.to_dict()["state"] == "present"


def test_finding_state_round_trip() -> None:
    f = Finding(kind="tracker", subject="x", confidence=Confidence.LOW,
                state=FindingState.NETWORK_OBSERVED)
    assert Finding.from_dict(f.to_dict()) == f


def test_finding_attributes_round_trip() -> None:
    f = Finding(kind="tracker", subject="AdMob", confidence=Confidence.HIGH,
                attributes={"category": "ads", "owner": "Google"})
    assert Finding.from_dict(f.to_dict()) == f
    assert f.to_dict()["attributes"] == {"category": "ads", "owner": "Google"}


def test_density_score() -> None:
    from dumpa.core.report import density_score
    facts = AppFacts(input_sha256="a" * 64, input_size=2 * 1024 * 1024)
    report = Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk", facts=facts,
        findings=[
            Finding(kind="tracker", subject="AdMob", confidence=Confidence.HIGH,
                    attributes={"category": "ads", "owner": "Google"}),
            Finding(kind="tracker", subject="Amplitude", confidence=Confidence.HIGH,
                    attributes={"category": "analytics", "owner": "Amplitude"}),
            Finding(kind="engine", subject="Unity", confidence=Confidence.HIGH),
        ],
    )
    d = density_score(report)
    assert d["trackers"] == 2
    assert d["companies"] == 2
    assert d["ad_sdks"] == 1
    assert d["per_mb"] == 1.0


def test_location_omits_none() -> None:
    loc = Location(domain="x.com")
    assert loc.to_dict() == {"domain": "x.com"}


def test_evidence_omits_none() -> None:
    ev = Evidence(description="hi")
    assert ev.to_dict() == {"description": "hi"}


def test_schema_version_default() -> None:
    assert _sample().to_dict()["schema_version"] == 1


def test_markdown_renders_key_fields() -> None:
    md = render_markdown(_sample())
    assert "# dumpa report — com.example.game" in md
    assert "firebase-analytics" in md
    assert "apk is unsigned" in md
    assert "v2+v3" in md


def test_markdown_no_findings() -> None:
    report = _sample()
    bare = Report(
        dumpa_version=report.dumpa_version, created=report.created,
        input_path=report.input_path, facts=report.facts,
    )
    md = render_markdown(bare)
    assert "## Findings\n_none_" in md
