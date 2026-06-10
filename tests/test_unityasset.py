"""UnityPy adapter (core/unityasset).

Pure helpers (string-walk, script coercion, object extraction, classification) are tested
with fake UnityPy object readers, so the bulk needs no UnityPy install. The one test that
actually drives UnityPy.load (fail-soft on garbage) guards with importorskip. Real
TextAsset extraction from a true container is covered by the gitignored golden-apk corpus.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.core import unityasset

# --- fakes ------------------------------------------------------------------

class _Type:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeObj:
    """Duck-types the bits of a UnityPy ObjectReader the adapter touches."""

    def __init__(self, type_name: str, path_id: int = 1, *, data: object = None,
                 typetree: object = None, peek: str | None = None) -> None:
        self.type = _Type(type_name)
        self.path_id = path_id
        self._data = data
        self._typetree = typetree
        self._peek = peek

    def read(self) -> object:
        return self._data

    def read_typetree(self) -> object:
        return self._typetree

    def peek_name(self) -> str | None:
        return self._peek


class _Data:
    def __init__(self, **kw: object) -> None:
        self.__dict__.update(kw)


# --- _coerce_script ---------------------------------------------------------

def test_coerce_script_bytes_truncates() -> None:
    text, raw = unityasset._coerce_script(b"hello world", 5)
    assert raw == b"hello"
    assert text == "hello"


def test_coerce_script_str() -> None:
    text, raw = unityasset._coerce_script("abc", 100)
    assert text == "abc"
    assert raw == b"abc"


# --- _walk_strings ----------------------------------------------------------

def test_walk_strings_nested_and_skips_nonstr() -> None:
    tree = {"m_Name": "Cfg", "url": "https://x.test", "n": 5, "kids": [{"k": "v"}, 7, ""]}
    got = unityasset._walk_strings(tree, max_count=10, max_len=100)
    assert "https://x.test" in got and "Cfg" in got and "v" in got
    assert "" not in got  # empty strings dropped


def test_walk_strings_bounds_count_and_len() -> None:
    tree = {"a": "x" * 50, "b": "y", "c": "z"}
    got = unityasset._walk_strings(tree, max_count=2, max_len=4)
    assert len(got) == 2
    assert all(len(s) <= 4 for s in got)


# --- _class_of --------------------------------------------------------------

def test_class_of_selects_text_and_mono_only() -> None:
    assert unityasset._class_of(_FakeObj("TextAsset")) == "TextAsset"
    assert unityasset._class_of(_FakeObj("MonoBehaviour")) == "MonoBehaviour"
    assert unityasset._class_of(_FakeObj("Texture2D")) is None


# --- _name_of ---------------------------------------------------------------

def test_name_of_prefers_m_name_then_peek() -> None:
    assert unityasset._name_of(_Data(m_Name="Real"), _FakeObj("TextAsset")) == "Real"
    assert unityasset._name_of(_Data(), _FakeObj("TextAsset", peek="Peeked")) == "Peeked"
    assert unityasset._name_of(_Data(), _FakeObj("TextAsset")) == ""


# --- _extract_object --------------------------------------------------------

def test_extract_textasset() -> None:
    obj = _FakeObj("TextAsset", path_id=42, data=_Data(m_Name="config", m_Script="api=https://a.test"))
    [es] = unityasset._extract_object(obj, "assets/x.assets", max_bytes_per_obj=1000,
                                      max_strings_per_obj=10)
    assert es.class_name == "TextAsset"
    assert es.asset_name == "config"
    assert es.path_id == 42
    assert es.text == "api=https://a.test"
    assert es.raw == b"api=https://a.test"


def test_extract_textasset_empty_script_skipped() -> None:
    obj = _FakeObj("TextAsset", data=_Data(m_Name="e", m_Script=""))
    assert unityasset._extract_object(obj, "x", max_bytes_per_obj=10, max_strings_per_obj=10) == []


def test_extract_monobehaviour_walks_strings() -> None:
    obj = _FakeObj("MonoBehaviour", path_id=7,
                   typetree={"m_Name": "Beh", "endpoint": "https://m.test", "count": 3})
    out = unityasset._extract_object(obj, "x.assets", max_bytes_per_obj=1000, max_strings_per_obj=10)
    texts = {e.text for e in out}
    assert "https://m.test" in texts
    assert all(e.class_name == "MonoBehaviour" and e.raw is None for e in out)
    assert any(e.asset_name == "Beh" for e in out)


def test_extract_skips_other_classes() -> None:
    assert unityasset._extract_object(_FakeObj("Texture2D"), "x", max_bytes_per_obj=10,
                                      max_strings_per_obj=10) == []


# --- available / version ----------------------------------------------------

def test_available_reflects_find_spec(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.util

    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    assert unityasset.available() is False
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object())
    assert unityasset.available() is True


# --- parse_container fail-soft (drives real UnityPy) ------------------------

def test_parse_container_failsoft_on_garbage(tmp_path: Path) -> None:
    pytest.importorskip("UnityPy")
    bad = tmp_path / "not.assets"
    bad.write_bytes(b"this is not a unity serialized file" * 4)
    assert unityasset.parse_container(bad, "not.assets") == []
