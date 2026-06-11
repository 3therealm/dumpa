"""commands.doctor: advisory --full environment checks."""

from __future__ import annotations

from dumpa.commands.doctor import (
    EnvCheck,
    _check_python,
    _check_rule_bundles,
    _check_signature_db,
    _check_unitypy,
    _full_checks,
)
from dumpa.core import unityasset
from dumpa.core.config import load_config
from dumpa.core.tools import build_default_registry


def test_full_checks_cover_all_dimensions() -> None:
    config = load_config()
    registry = build_default_registry(config.tool_paths)
    checks = _full_checks(config, registry)
    names = {c.name for c in checks}
    assert names == {
        "python runtime", "java runtime", "android sdk",
        "signing config", "rule bundles", "signature db", "unitypy",
    }
    assert all(isinstance(c, EnvCheck) for c in checks)
    assert all(c.status in ("ok", "warn", "info") for c in checks)


def test_python_check_reports_version() -> None:
    check = _check_python()
    assert check.status == "info"
    assert check.detail[0].isdigit()  # e.g. "3.14.0"


def test_rule_bundles_listed() -> None:
    check = _check_rule_bundles()
    assert check.status == "info"
    assert "engines" in check.detail
    assert "trackers" in check.detail


def test_signature_db_reports_versions() -> None:
    check = _check_signature_db()
    assert check.status == "info"
    # each entry is "<bundle>=<version>"
    assert "engines=" in check.detail


def test_unitypy_check_reports_presence(monkeypatch) -> None:
    monkeypatch.setattr(unityasset, "available", lambda: False)
    absent = _check_unitypy()
    assert absent.status == "info"
    assert "not installed" in absent.detail

    monkeypatch.setattr(unityasset, "available", lambda: True)
    monkeypatch.setattr(unityasset, "unitypy_version", lambda: "1.25.0")
    present = _check_unitypy()
    assert present.detail == "1.25.0"
