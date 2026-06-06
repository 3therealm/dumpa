"""parse_badging: triage fields from aapt dump badging text."""

from __future__ import annotations

from dumpa.tools.aapt import parse_badging

_BADGING = """\
package: name='com.example.game' versionCode='42' versionName='1.2.3' platformBuildVersionName='14'
sdkVersion:'24'
targetSdkVersion:'34'
uses-permission: name='android.permission.INTERNET'
uses-permission: name='android.permission.ACCESS_NETWORK_STATE'
uses-permission-sdk-23: name='android.permission.FOREGROUND_SERVICE'
application-label:'Game'
native-code: 'arm64-v8a' 'armeabi-v7a'
"""


def test_parse_full() -> None:
    info = parse_badging(_BADGING)
    assert info.package == "com.example.game"
    assert info.version_code == "42"
    assert info.version_name == "1.2.3"
    assert info.min_sdk == "24"
    assert info.target_sdk == "34"
    assert info.abis == ("arm64-v8a", "armeabi-v7a")
    assert info.permissions == (
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.FOREGROUND_SERVICE",
    )
    assert info.permission_count == 3


def test_parse_empty_is_blank() -> None:
    info = parse_badging("")
    assert info.package is None
    assert info.abis == ()
    assert info.permission_count == 0


def test_parse_no_native_code() -> None:
    info = parse_badging("package: name='x.y' versionCode='1' versionName='1'\n")
    assert info.abis == ()
