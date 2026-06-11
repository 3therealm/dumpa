"""Endpoint purpose classification: core.endpoints + the enrich_endpoint_purpose pass."""

from __future__ import annotations

from pathlib import Path

from dumpa.core.endpoints import load_endpoint_rules
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace
from dumpa.scanners import enrich_endpoint_purpose


def test_classify_host_suffix() -> None:
    t = load_endpoint_rules()
    assert t.classify("firebaseio.com", ()) == "firebase"
    assert t.classify("d111.cloudfront.net", ()) == "cdn"          # label-boundary suffix
    assert t.classify("notcloudfront.net", ()) is None             # not a boundary match


def test_classify_url_path_beats_host() -> None:
    t = load_endpoint_rules()
    assert t.classify("unknown.example", ("/openrtb2/auction",)) == "ad-auction"
    assert t.classify("anything.example", ("/v1/config",)) is None


def test_classify_longest_host_wins() -> None:
    t = load_endpoint_rules()
    # firebaseremoteconfig.googleapis.com is remote-config, not a broad firebase match.
    assert t.classify("firebaseremoteconfig.googleapis.com", ()) == "remote-config"


def _endpoint(subject: str, *, paths: str | None = None, purpose: str | None = None) -> Finding:
    attrs: dict[str, str] = {}
    if paths is not None:
        attrs["paths"] = paths
    if purpose is not None:
        attrs["purpose"] = purpose
    return Finding(
        kind="endpoint", subject=subject, confidence=Confidence.LOW,
        state=FindingState.PRESENT, attributes=attrs,
        evidence=[Evidence(description="u", snippet="u", tool="endpoint")],
        locations=[Location(file_path="a.dex", domain=subject)])


def test_enrich_tags_purpose(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    out = enrich_endpoint_purpose([_endpoint("firebaseio.com")], ws)
    assert out[0].attributes["purpose"] == "firebase"


def test_enrich_uses_paths_attribute(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    out = enrich_endpoint_purpose([_endpoint("bid.example", paths="/openrtb2/auction; /x")], ws)
    assert out[0].attributes["purpose"] == "ad-auction"


def test_enrich_dedupes_by_subject(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    first = _endpoint("dup.example", paths="/keep")
    second = _endpoint("dup.example", paths="/drop")
    out = enrich_endpoint_purpose([first, second], ws)
    eps = [f for f in out if f.kind == "endpoint"]
    assert len(eps) == 1
    assert eps[0].attributes.get("paths") == "/keep"   # first wins


def test_enrich_idempotent_and_preserves_existing_purpose(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    once = enrich_endpoint_purpose([_endpoint("firebaseio.com")], ws)
    twice = enrich_endpoint_purpose(once, ws)
    assert twice[0].attributes["purpose"] == "firebase"
    # a pre-set purpose is never overwritten
    custom = enrich_endpoint_purpose([_endpoint("firebaseio.com", purpose="custom")], ws)
    assert custom[0].attributes["purpose"] == "custom"


def test_enrich_leaves_non_endpoints_untouched(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    tracker = Finding(kind="tracker", subject="X", confidence=Confidence.HIGH,
                      state=FindingState.PRESENT, attributes={}, evidence=[], locations=[])
    out = enrich_endpoint_purpose([tracker], ws)
    assert out == [tracker]
