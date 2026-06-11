"""probe_engine_from_names: glob-only engine detection over a zip namelist (for `info`)."""

from __future__ import annotations

from dumpa.core.rules import probe_engine_from_names


def test_unity_via_native_lib() -> None:
    assert probe_engine_from_names(["lib/arm64-v8a/libil2cpp.so", "classes.dex"]) == "Unity"


def test_unity_via_assets_only() -> None:
    # No native lib in this (e.g. base) apk, but the Unity data dir is present.
    assert probe_engine_from_names(["assets/bin/Data/managed/x.dll"]) == "Unity"


def test_cocos_and_flutter_and_godot() -> None:
    assert probe_engine_from_names(["lib/arm64-v8a/libcocos2djs.so"]) == "Cocos2d-x"
    assert probe_engine_from_names(["assets/flutter_assets/AssetManifest.json"]) == "Flutter"
    assert probe_engine_from_names(["assets/game.pck"]) == "Godot"


def test_no_engine() -> None:
    assert probe_engine_from_names([]) is None
    assert probe_engine_from_names(["classes.dex", "AndroidManifest.xml", "res/x.png"]) is None


def test_high_confidence_wins_over_medium() -> None:
    # Unity (high, native lib) and Ren'Py (medium, .rpa) both present -> Unity.
    names = ["lib/arm64-v8a/libunity.so", "assets/game/script.rpa"]
    assert probe_engine_from_names(names) == "Unity"
