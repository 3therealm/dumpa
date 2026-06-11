"""Data Safety page parsing + the disk cache round-trip."""

from __future__ import annotations

import datetime
from pathlib import Path

from dumpa.core.datasafety import (
    DataSafetyDisclosure,
    _parse_datasafety,
    _write_cache,
    fetch_datasafety,
    is_valid_package,
)

# Mirrors the real page layout: two data sections (each listing its data-type
# categories as <h3>), then a "Security practices" section that bounds the second.
_FIXTURE = """\
<h2 class="Cs5R8e">Data shared</h2><div>blurb</div>
<div><h3 class="aFEzEb">Device or other IDs</h3><div class="fozKzd">Device or other IDs</div></div>
<h2 class="Cs5R8e">Data collected</h2><div>blurb</div>
<div><h3 class="aFEzEb">Location</h3></div>
<div><h3 class="aFEzEb">Personal info</h3></div>
<div><h3 class="aFEzEb">App info and performance</h3></div>
<h2>Security practices</h2><div><h3>Data is encrypted in transit</h3></div>
"""


def test_parse_extracts_collected_and_shared() -> None:
    d = _parse_datasafety(_FIXTURE, "com.example.app",
                          "https://play.google.com/x", "2026-06-09T00:00:00+00:00")
    assert d is not None
    assert d.shared == ("Device or other IDs",)
    assert d.collected == ("App info and performance", "Location", "Personal info")
    # Security-practices h3 must not leak into the collected set.
    assert "Data is encrypted in transit" not in d.labels()
    assert d.labels() == {"Device or other IDs", "Location", "Personal info",
                          "App info and performance"}


def test_parse_returns_none_when_no_sections() -> None:
    assert _parse_datasafety("<html><body>no disclosure here</body></html>",
                             "com.example.app", "u", "t") is None


def test_is_valid_package() -> None:
    assert is_valid_package("com.example.app")
    assert not is_valid_package("not a package")
    assert not is_valid_package("")


def test_cache_round_trip(tmp_path: Path) -> None:
    cache_dir = tmp_path / "datasafety"
    now = datetime.datetime(2026, 6, 9, tzinfo=datetime.UTC)
    disclosure = DataSafetyDisclosure(
        package="com.example.app", url="https://play.google.com/x",
        fetched=now.isoformat(), collected=("Location",), shared=("Device or other IDs",))
    _write_cache(cache_dir, disclosure)

    # Read back from cache with network disabled -> identical disclosure.
    got = fetch_datasafety("com.example.app", cache_dir=cache_dir, allow_network=False,
                           timeout=5, ttl_days=30, now=now)
    assert got == disclosure


def test_cache_expires(tmp_path: Path) -> None:
    cache_dir = tmp_path / "datasafety"
    written = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    disclosure = DataSafetyDisclosure(
        package="com.example.app", url="u", fetched=written.isoformat(),
        collected=("Location",), shared=())
    _write_cache(cache_dir, disclosure)
    # 200 days later, past the 30-day TTL; with no network the lookup misses.
    later = written + datetime.timedelta(days=200)
    assert fetch_datasafety("com.example.app", cache_dir=cache_dir, allow_network=False,
                            timeout=5, ttl_days=30, now=later) is None


def test_invalid_package_no_fetch(tmp_path: Path) -> None:
    assert fetch_datasafety("nope", cache_dir=tmp_path, allow_network=False,
                            timeout=5, ttl_days=30) is None
