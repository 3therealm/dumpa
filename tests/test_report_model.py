"""core.report: serialization round-trip, None-omission, markdown render."""

from __future__ import annotations

import csv
import io
import json

from dumpa.core.report import (
    AppFacts,
    CompanyRollup,
    Confidence,
    DomainRecord,
    Evidence,
    Finding,
    FindingState,
    Location,
    Report,
    companies,
    domain_records,
    render_blocklist,
    render_domains_csv,
    render_html,
    render_markdown,
    render_trackers_csv,
    report_domains,
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


def test_location_dex_field_round_trip() -> None:
    loc = Location(file_path="classes.dex", file_offset=42, dex_class="com.x.A",
                   dex_method="foo", dex_field="com.x.A.KEY", dex_bytecode_offset=3)
    restored = Location.from_dict(loc.to_dict())
    assert restored == loc
    assert restored.dex_field == "com.x.A.KEY"
    assert restored.dex_bytecode_offset == 3


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


def test_tracker_product_and_purpose_defaults() -> None:
    from dumpa.core.report import tracker_product, tracker_purpose
    # Firebase-family subject -> product family from the subject map; purpose from category.
    fa = Finding(kind="tracker", subject="Firebase Analytics", confidence=Confidence.HIGH,
                 attributes={"category": "analytics", "owner": "Google"})
    assert tracker_product(fa) == "Firebase"
    assert tracker_purpose(fa) == "measure app usage & behavior"
    # Standalone SDK -> product falls back to the subject (the SDK is its own product).
    amp = Finding(kind="tracker", subject="Amplitude", confidence=Confidence.HIGH,
                  attributes={"category": "analytics"})
    assert tracker_product(amp) == "Amplitude"


def test_tracker_product_and_purpose_overrides() -> None:
    from dumpa.core.report import tracker_product, tracker_purpose
    f = Finding(kind="tracker", subject="Custom SDK", confidence=Confidence.HIGH,
                attributes={"category": "ads", "product": "MyProduct", "purpose": "custom use"})
    assert tracker_product(f) == "MyProduct"
    assert tracker_purpose(f) == "custom use"


def test_markdown_renders_product_and_purpose() -> None:
    report = Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
        findings=[Finding(kind="tracker", subject="Firebase Analytics",
                          confidence=Confidence.HIGH,
                          attributes={"category": "analytics", "owner": "Google"})],
    )
    md = render_markdown(report)
    assert "(Firebase)" in md                       # product family, distinct from subject
    assert "measure app usage & behavior" in md     # category-default purpose


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


# --- C5: blocklist scoping + formats -------------------------------------


def _scoped() -> Report:
    """First-party endpoint (no owner) + a tracker-owned host."""
    return Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
        findings=[
            Finding(kind="endpoint", subject="api.myapp.example", confidence=Confidence.LOW),
            Finding(kind="tracker", subject="firebase-analytics", confidence=Confidence.HIGH,
                    attributes={"owner": "Google", "category": "analytics"},
                    locations=[Location(domain="firebase.googleapis.com")]),
        ],
    )


def test_report_domains_default_includes_first_party() -> None:
    assert "api.myapp.example" in report_domains(_scoped())
    assert "firebase.googleapis.com" in report_domains(_scoped())


def test_report_domains_trackers_only_drops_first_party() -> None:
    scoped = report_domains(_scoped(), trackers_only=True)
    assert scoped == ["firebase.googleapis.com"]


def test_report_domains_trackers_only_keeps_owned_endpoint() -> None:
    report = Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
        findings=[
            Finding(kind="endpoint", subject="ads.example", confidence=Confidence.LOW,
                    attributes={"owner": "AdCo"}),
        ],
    )
    assert report_domains(report, trackers_only=True) == ["ads.example"]


def _single(domain: str = "d", owner: str | None = None) -> Report:
    attrs = {"owner": owner} if owner else {}
    return Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
        findings=[
            Finding(kind="tracker", subject="sdk", confidence=Confidence.HIGH,
                    attributes=attrs, locations=[Location(domain=domain)]),
        ],
    )


def test_render_blocklist_hosts() -> None:
    assert render_blocklist(_single(), "hosts") == "0.0.0.0 d\n"


def test_render_blocklist_adguard() -> None:
    assert render_blocklist(_single(), "adguard") == "||d^\n"


def test_render_blocklist_nextdns() -> None:
    assert render_blocklist(_single(), "nextdns") == "d\n"


def test_render_blocklist_rethinkdns() -> None:
    assert render_blocklist(_single(), "rethinkdns") == "! dumpa\nd\n"


def test_render_blocklist_trackercontrol() -> None:
    out = render_blocklist(_single(owner="Google"), "trackercontrol")
    assert out == "# Google\n0.0.0.0 d\n"


def test_trackercontrol_groups_by_owner() -> None:
    report = Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
        findings=[
            Finding(kind="tracker", subject="ga", confidence=Confidence.HIGH,
                    attributes={"owner": "Google"},
                    locations=[Location(domain="g1.example"), Location(domain="g2.example")]),
            Finding(kind="endpoint", subject="unknown.example", confidence=Confidence.LOW),
        ],
    )
    out = render_blocklist(report, "trackercontrol")
    lines = out.splitlines()
    assert "# Google" in lines
    gi = lines.index("# Google")
    assert lines[gi + 1] == "0.0.0.0 g1.example"
    assert lines[gi + 2] == "0.0.0.0 g2.example"
    assert "# (unattributed)" in lines
    ui = lines.index("# (unattributed)")
    assert lines[ui + 1] == "0.0.0.0 unknown.example"


def test_render_blocklist_scope_threads_into_every_format() -> None:
    for fmt in ("hosts", "adguard", "nextdns", "rethinkdns", "trackercontrol"):
        scoped = render_blocklist(_scoped(), fmt, trackers_only=True)
        assert "api.myapp.example" not in scoped
        assert "firebase.googleapis.com" in scoped


def test_render_blocklist_empty_is_blank_for_all_formats() -> None:
    bare = Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
    )
    for fmt in ("hosts", "adguard", "nextdns", "rethinkdns", "trackercontrol"):
        assert render_blocklist(bare, fmt) == ""


def test_export_reenriches_domain_aware_only(tmp_path, monkeypatch) -> None:
    from dumpa.commands import export as export_cmd

    report = _single()
    calls: list[str] = []

    def spy_enrich(findings, ws):
        calls.append("called")
        return findings

    monkeypatch.setattr(export_cmd, "_load_report", lambda ws, *, use_cache=True: report)
    monkeypatch.setattr(export_cmd, "enrich_domain_attribution", spy_enrich)

    # every domain-aware format re-enriches the loaded report
    for i, fmt in enumerate(export_cmd._DOMAIN_AWARE):
        calls.clear()
        export_cmd.export(tmp_path, fmt=fmt, out=tmp_path / f"aware-{i}.txt")
        assert calls == ["called"], fmt

    # json and md are "report as built" — never re-enriched
    for fmt in ("json", "md", "markdown"):
        calls.clear()
        export_cmd.export(tmp_path, fmt=fmt, out=tmp_path / f"{fmt}.txt")
        assert calls == [], fmt


# --- C6: company grouping ------------------------------------------------


def _companies_report() -> Report:
    return Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
        findings=[
            Finding(kind="tracker", subject="AdMob", confidence=Confidence.HIGH,
                    attributes={"owner": "Google", "category": "ads"},
                    locations=[Location(domain="googleads.g.doubleclick.net")]),
            Finding(kind="tracker", subject="Firebase Analytics", confidence=Confidence.HIGH,
                    attributes={"owner": "Google", "category": "analytics"},
                    locations=[Location(domain="firebase.googleapis.com")]),
            Finding(kind="tracker", subject="AppLovin MAX", confidence=Confidence.HIGH,
                    attributes={"owner": "AppLovin", "category": "ad mediation"}),
            Finding(kind="tracker", subject="MysterySDK", confidence=Confidence.LOW),
        ],
    )


def test_companies_groups_by_owner() -> None:
    rollups = companies(_companies_report())
    assert set(rollups) == {"Google", "AppLovin"}  # MysterySDK (no owner) excluded
    google = rollups["Google"]
    assert isinstance(google, CompanyRollup)
    assert google.trackers == ["AdMob", "Firebase Analytics"]
    assert google.categories == ["ads", "analytics"]
    assert google.domains == ["firebase.googleapis.com", "googleads.g.doubleclick.net"]


def test_companies_mediation_adapters_count() -> None:
    rollups = companies(_companies_report())
    assert rollups["AppLovin"].mediation_adapters == 1
    assert rollups["Google"].mediation_adapters == 0


def test_density_score_mediation_adapters() -> None:
    from dumpa.core.report import density_score
    assert density_score(_companies_report())["mediation_adapters"] == 1


def test_markdown_companies_line() -> None:
    md = render_markdown(_companies_report())
    assert "companies: AppLovin (1), Google (2)" in md


# --- HTML exporter -------------------------------------------------------


def test_html_renders_key_fields() -> None:
    out = render_html(_sample())
    assert out.lstrip().startswith("<!DOCTYPE html>")
    assert "com.example.game" in out
    assert "firebase-analytics" in out
    assert "apk is unsigned" in out
    # same data as markdown: signing schemes joined
    assert "v2+v3" in out


def test_html_is_self_contained() -> None:
    out = render_html(_sample())
    # inline style, no external asset references
    assert "<style>" in out
    assert "src=" not in out
    assert 'href="http' not in out


def test_html_no_findings() -> None:
    bare = Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024),
    )
    out = render_html(bare)
    assert "<!DOCTYPE html>" in out
    assert "Trackers" in out  # section still rendered, just empty


def test_html_escapes_dynamic_text() -> None:
    """Report text is attacker-controlled; it must never inject live markup."""
    evil = '<script>alert(1)</script>'
    report = Report(
        dumpa_version="0.1.0", created="t", input_path="/x.apk",
        facts=AppFacts(input_sha256="a" * 64, input_size=1024, package=evil),
        findings=[Finding(kind="tracker", subject=evil, confidence=Confidence.HIGH)],
        warnings=[evil],
    )
    out = render_html(report)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
