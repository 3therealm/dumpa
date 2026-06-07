"""Structured ManifestInfo extraction from decoded AXML."""

from __future__ import annotations

from pathlib import Path

import pytest
from _axml_build import build_axml

from dumpa.core.errors import AxmlError
from dumpa.core.manifest import load_manifest, parse_manifest_bytes
from dumpa.core.workspace import Workspace


def _full_manifest() -> bytes:
    return build_axml(("manifest", {
        "package": "com.example.game",
        "versionCode": "42",
        "versionName": "1.2.3",
    }, [
        ("uses-sdk", {"minSdkVersion": "24", "targetSdkVersion": "34"}, []),
        ("uses-permission", {"name": "android.permission.INTERNET"}, []),
        ("uses-permission", {"name": "android.permission.ACCESS_FINE_LOCATION"}, []),
        ("application", {"debuggable": True, "allowBackup": False}, [
            ("activity", {"name": ".Main", "exported": True}, [
                ("intent-filter", {"autoVerify": True}, [
                    ("action", {"name": "android.intent.action.VIEW"}, []),
                    ("category", {"name": "android.intent.category.BROWSABLE"}, []),
                    ("data", {"scheme": "https", "host": "play.example.com"}, []),
                ]),
            ]),
            ("service", {"name": ".SyncService"}, []),                       # implicit (no filter)
            ("receiver", {"name": ".Boot", "exported": False}, [
                ("intent-filter", {}, [
                    ("action", {"name": "android.intent.action.BOOT_COMPLETED"}, []),
                ]),
            ]),
        ]),
    ]))


def test_package_and_version() -> None:
    m = parse_manifest_bytes(_full_manifest())
    assert m.package == "com.example.game"
    assert m.version_code == "42"
    assert m.version_name == "1.2.3"
    assert m.min_sdk == "24"
    assert m.target_sdk == "34"


def test_permissions_and_flags() -> None:
    m = parse_manifest_bytes(_full_manifest())
    assert m.permissions == (
        "android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION",
    )
    assert m.debuggable is True
    assert m.allow_backup is False


def test_components_and_exported() -> None:
    m = parse_manifest_bytes(_full_manifest())
    by_name = {c.name: c for c in m.components}
    assert set(by_name) == {".Main", ".SyncService", ".Boot"}

    main = by_name[".Main"]
    assert main.type == "activity"
    assert main.exported is True
    assert main.exported_effective is True

    svc = by_name[".SyncService"]
    assert svc.exported is None            # not declared
    assert svc.exported_effective is False  # no intent filter -> not exported

    boot = by_name[".Boot"]
    assert boot.exported is False
    assert boot.exported_effective is False


def test_intent_filter_details() -> None:
    m = parse_manifest_bytes(_full_manifest())
    main = next(c for c in m.components if c.name == ".Main")
    flt = main.intent_filters[0]
    assert flt.actions == ("android.intent.action.VIEW",)
    assert "android.intent.category.BROWSABLE" in flt.categories
    assert flt.data[0].scheme == "https"
    assert flt.data[0].host == "play.example.com"
    assert flt.auto_verify is True


def test_exported_components_helper() -> None:
    m = parse_manifest_bytes(_full_manifest())
    exported = {c.name for c in m.exported_components}
    assert exported == {".Main"}            # implicit service + explicit-false receiver excluded


def test_no_root_raises() -> None:
    import struct
    empty = struct.pack("<HHI", 0x0003, 8, 8)   # header only, no elements
    with pytest.raises(AxmlError, match="no root"):
        parse_manifest_bytes(empty)


def test_load_manifest_from_workspace(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    (extracted / "AndroidManifest.xml").write_bytes(_full_manifest())
    ws = Workspace(root=tmp_path)
    m = load_manifest(ws)
    assert m is not None
    assert m.package == "com.example.game"


def test_load_manifest_absent_is_none(tmp_path: Path) -> None:
    (tmp_path / "extracted").mkdir()
    assert load_manifest(Workspace(root=tmp_path)) is None
