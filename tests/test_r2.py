"""core/r2 wrapper: fail-soft, timeout, entropy parsing — r2pipe fully mocked."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from dumpa.core import r2


class FakePipe:
    """Minimal r2pipe stand-in: canned cmd/cmdj responses, optional hang on `aa`."""

    def __init__(self, *, sections=None, functions=None, entropy="entropy 7.95",
                 hang: float = 0.0) -> None:
        self._sections = sections if sections is not None else []
        self._functions = functions if functions is not None else []
        self._entropy = entropy
        self._hang = hang
        self.killed = False
        self.quit_called = False

    def cmd(self, c: str) -> str:
        if c == "aa" and self._hang:
            time.sleep(self._hang)
        if c.startswith("ph entropy"):
            return self._entropy
        return ""

    def cmdj(self, c: str):
        if c == "iSj":
            return self._sections
        if c == "aflj":
            return self._functions
        return None

    def quit(self) -> None:
        self.quit_called = True

    @property
    def process(self):
        pipe = self

        class _Proc:
            def kill(self_inner) -> None:
                pipe.killed = True

        return _Proc()


def _so(tmp_path: Path, size: int = 64) -> Path:
    p = tmp_path / "lib.so"
    p.write_bytes(b"\x00" * size)
    return p


# --- entropy parsing ---------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("entropy 7.95", 7.95),
    ("7.0", 7.0),
    ("0.000000", 0.0),
    ("no number here", None),
    ("", None),
    (None, None),
])
def test_parse_entropy(text, expected) -> None:
    assert r2.parse_entropy(text) == expected


# --- happy path --------------------------------------------------------------

def test_analyze_happy_path(tmp_path: Path, monkeypatch) -> None:
    sections = [{"name": ".text", "vaddr": 0x1000, "paddr": 0x400,
                 "size": 2048, "perm": "-r-x"}]
    functions = [{"name": "sym.main", "offset": 0x1100, "size": 64, "nbbs": 3}]
    fake = FakePipe(sections=sections, functions=functions, entropy="7.91")
    monkeypatch.setattr(r2, "_open_r2pipe", lambda _p: fake)

    a = r2.analyze(_so(tmp_path), version="radare2 5.9.0")
    assert a is not None
    assert a.version == "radare2 5.9.0"
    assert len(a.sections) == 1
    sec = a.sections[0]
    assert sec.name == ".text" and sec.paddr == 0x400 and sec.vaddr == 0x1000
    assert sec.entropy == 7.91
    assert len(a.functions) == 1 and a.functions[0].vaddr == 0x1100
    assert fake.quit_called


# --- fail-soft ---------------------------------------------------------------

def test_analyze_none_when_r2pipe_unavailable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(r2, "_open_r2pipe", lambda _p: None)
    assert r2.analyze(_so(tmp_path)) is None


def test_analyze_skips_oversized(tmp_path: Path, monkeypatch) -> None:
    called: list[int] = []
    monkeypatch.setattr(r2, "_open_r2pipe", lambda _p: called.append(1))
    assert r2.analyze(_so(tmp_path, size=2048), max_bytes=1024) is None
    assert called == []                       # never even opened


def test_analyze_returns_none_on_timeout(tmp_path: Path, monkeypatch) -> None:
    fake = FakePipe(hang=5.0)
    monkeypatch.setattr(r2, "_open_r2pipe", lambda _p: fake)
    assert r2.analyze(_so(tmp_path), timeout=1) is None
    assert fake.killed


def test_analyze_returns_none_on_command_error(tmp_path: Path, monkeypatch) -> None:
    class Boom(FakePipe):
        def cmdj(self, c: str):
            raise RuntimeError("r2 exploded")

    fake = Boom()
    monkeypatch.setattr(r2, "_open_r2pipe", lambda _p: fake)
    assert r2.analyze(_so(tmp_path)) is None


def test_analyze_tolerates_empty_results(tmp_path: Path, monkeypatch) -> None:
    fake = FakePipe(sections=[], functions=[])
    monkeypatch.setattr(r2, "_open_r2pipe", lambda _p: fake)
    a = r2.analyze(_so(tmp_path))
    assert a is not None and a.sections == [] and a.functions == []
