"""core.report: serialization round-trip, None-omission, markdown render."""

from __future__ import annotations

import csv
import io
import json

from dumpa.core.report import (
    AppFacts,
    Confidence,
    DomainRecord,
    Evidence,
    Finding,
    FindingState,
    Location,
    Report,
    domain_records,
    render_domains_csv,
    render_markdown,
    render_trackers_csv,
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


# --- C4: CSV exporters ---------------------------------------------------


def _attributed() -> Report:
    """A report with an attributed endpoint + a tracker carrying a domain location."""
    return Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
        findings=[
            Finding(
                kind="tracker", subject="firebase-analytics", confidence=Confidence.HIGH,
                state=FindingState.REFERENCED,
                attributes={"owner": "Google", "category": "analytics"},
                locations=[
                    Location(domain="firebase.googleapis.com",
                             file_path="lib/arm64-v8a/libapp.so", file_offset=4096),
                    Location(domain="firebase.googleapis.com", file_path="classes.dex"),
                ],
            ),
            Finding(
                kind="endpoint", subject="firebase.googleapis.com", confidence=Confidence.LOW,
                attributes={"owner": "Google", "category": "analytics"},
            ),
            Finding(
                kind="endpoint", subject="api.example.com", confidence=Confidence.LOW,
            ),
        ],
    )


def test_domain_records_one_per_unique_domain() -> None:
    records = domain_records(_attributed())
    assert [r.domain for r in records] == ["api.example.com", "firebase.googleapis.com"]
    fb = records[1]
    assert isinstance(fb, DomainRecord)
    assert fb.owner == "Google"
    assert fb.category == "analytics"
    assert fb.subject == "firebase-analytics"
    assert fb.first_file == "lib/arm64-v8a/libapp.so"
    assert fb.first_offset == 4096
    # endpoint-only domain with no domain-bearing location
    other = records[0]
    assert other.owner is None
    assert other.first_file is None
    assert other.first_offset is None


def test_domain_records_tracker_first_owner() -> None:
    # endpoint precedes the owning tracker and disagrees on owner/category;
    # the tracker's attribution must win.
    report = Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
        findings=[
            Finding(kind="endpoint", subject="d.example.com", confidence=Confidence.LOW,
                    attributes={"owner": "WrongOwner", "category": "wrong"}),
            Finding(kind="tracker", subject="real-sdk", confidence=Confidence.HIGH,
                    attributes={"owner": "RightOwner", "category": "ads"},
                    locations=[Location(domain="d.example.com")]),
        ],
    )
    rec = domain_records(report)[0]
    assert rec.owner == "RightOwner"
    assert rec.category == "ads"
    assert rec.subject == "real-sdk"


def test_render_trackers_csv() -> None:
    rows = list(csv.reader(io.StringIO(render_trackers_csv(_attributed()))))
    assert rows[0] == ["subject", "owner", "category", "confidence", "state", "domains", "files"]
    assert rows[1] == [
        "firebase-analytics", "Google", "analytics", "high", "referenced",
        "firebase.googleapis.com", "classes.dex;lib/arm64-v8a/libapp.so",
    ]
    assert len(rows) == 2  # only the one tracker finding


def test_render_domains_csv() -> None:
    rows = list(csv.reader(io.StringIO(render_domains_csv(_attributed()))))
    assert rows[0] == ["domain", "owner", "category", "subject", "first_file", "first_offset"]
    assert rows[1] == ["api.example.com", "", "", "", "", ""]
    assert rows[2] == [
        "firebase.googleapis.com", "Google", "analytics", "firebase-analytics",
        "lib/arm64-v8a/libapp.so", "4096",
    ]


def test_csv_escaping_round_trips() -> None:
    report = Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
        findings=[
            Finding(kind="tracker", subject='weird,"name', confidence=Confidence.HIGH),
        ],
    )
    rows = list(csv.reader(io.StringIO(render_trackers_csv(report))))
    assert rows[1][0] == 'weird,"name'


def test_csv_empty_report_emits_header() -> None:
    bare = Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
    )
    assert render_trackers_csv(bare).splitlines() == [
        "subject,owner,category,confidence,state,domains,files"
    ]
    assert render_domains_csv(bare).splitlines() == [
        "domain,owner,category,subject,first_file,first_offset"
    ]


def test_export_wiring() -> None:
    from dumpa.commands.export import _NOT_YET, const_export_formats
    assert "csv" in const_export_formats
    assert "domains-csv" in const_export_formats
    assert "csv" not in _NOT_YET
