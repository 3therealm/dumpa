"""Data Safety disclosure-vs-observed comparison (the pure `compare`)."""

from __future__ import annotations

from dumpa.core.datasafety import DataSafetyDisclosure
from dumpa.core.privacy_compare import _load_category_map, compare
from dumpa.core.report import Confidence, Finding, FindingState


def _cap(subject: str, category: str) -> Finding:
    return Finding(kind="capability", subject=subject, confidence=Confidence.HIGH,
                   state=FindingState.PRESENT, attributes={"category": category})


def _tracker(subject: str, category: str) -> Finding:
    return Finding(kind="tracker", subject=subject, confidence=Confidence.MEDIUM,
                   state=FindingState.PRESENT, attributes={"category": category})


def _disclosure(*, collected: tuple[str, ...] = (),
                shared: tuple[str, ...] = ()) -> DataSafetyDisclosure:
    return DataSafetyDisclosure(package="com.example.app", url="https://play.google.com/x",
                                fetched="2026-06-09T00:00:00+00:00",
                                collected=collected, shared=shared)


def _gaps(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.kind == "data-safety-gap"]


def test_undisclosed_category_is_a_gap() -> None:
    disclosure = _disclosure(collected=("Location", "App info and performance"))
    findings = [
        _cap("Precise location", "location"),            # covered by Location -> no gap
        _cap("Advertising ID (AD_ID)", "advertising id"),  # needs Device or other IDs -> GAP
        _tracker("Firebase Crashlytics", "crash reporting"),  # covered by App info... -> no gap
    ]
    out = compare(disclosure, findings)
    gaps = _gaps(out)
    assert {g.subject for g in gaps} == {"advertising id"}
    gap = gaps[0]
    assert gap.confidence is Confidence.HIGH          # inherited from the capability
    assert gap.state is FindingState.PRESENT
    assert "Advertising ID (AD_ID)" in gap.attributes["observed_in"]
    # One informational disclosure finding is always emitted.
    info = [f for f in out if f.kind == "data-safety"]
    assert len(info) == 1
    assert info[0].attributes["collected"] == "Location, App info and performance"


def test_fully_disclosed_has_no_gaps() -> None:
    disclosure = _disclosure(collected=("Location", "Device or other IDs"))
    findings = [_cap("Precise location", "location"),
                _cap("Advertising ID (AD_ID)", "advertising id")]
    assert _gaps(compare(disclosure, findings)) == []


def test_uncomparable_categories_skipped() -> None:
    # bluetooth + clipboard have no Data Safety equivalent -> never flagged.
    disclosure = _disclosure()
    findings = [_cap("Bluetooth connect", "bluetooth"),
                Finding(kind="data-access", subject="Clipboard", confidence=Confidence.MEDIUM,
                        state=FindingState.REFERENCED, attributes={"category": "clipboard"})]
    assert _gaps(compare(disclosure, findings)) == []


def test_gap_inherits_strongest_state() -> None:
    disclosure = _disclosure()
    findings = [
        _cap("Advertising ID (AD_ID)", "advertising id"),  # present
        Finding(kind="data-access", subject="Advertising ID API", confidence=Confidence.MEDIUM,
                state=FindingState.REFERENCED, attributes={"category": "advertising id"}),
    ]
    gap = _gaps(compare(disclosure, findings))[0]
    assert gap.state is FindingState.REFERENCED       # stronger than PRESENT
    assert gap.confidence is Confidence.HIGH           # stronger than MEDIUM


def test_category_map_loads() -> None:
    m = _load_category_map()
    assert m["location"] == ("Location",)
    assert m["advertising id"] == ("Device or other IDs",)
    assert "bluetooth" not in m       # intentionally omitted
    assert "clipboard" not in m
