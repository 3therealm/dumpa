"""core/r2 wrapper: fail-soft CLI execution, JSON parsing, entropy, and caps."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from dumpa.core import r2
from dumpa.core.errors import ToolExecutionError, ToolTimeoutError


def _so(tmp_path: Path, data: bytes | None = None) -> Path:
    p = tmp_path / "lib.so"
    p.write_bytes(data if data is not None else b"\x00" * 64)
    return p


def _stdout(sections=None, functions=None) -> str:
    return json.dumps(sections if sections is not None else []) + "\n" + \
        json.dumps(functions if functions is not None else []) + "\n"


def _completed(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["radare2"], 0, stdout, "")


# --- entropy parsing ---------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("entropy 7.95", 7.95),
    ("7.0", 7.0),
    ("0.000000", 0.0),
    ("8.000000", 8.0),
    ("9.0", None),
    ("no number here", None),
    ("", None),
    (None, None),
])
def test_parse_entropy(text, expected) -> None:
    assert r2.parse_entropy(text) == expected


# --- happy path --------------------------------------------------------------

def test_analyze_happy_path(tmp_path: Path, monkeypatch) -> None:
    sections = [{"name": ".text", "vaddr": 0x1000, "paddr": 0,
                 "size": 2048, "perm": "-r-x"}]
    functions = [{"name": "sym.main", "offset": 0x1100, "size": 64, "nbbs": 3}]
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        assert kwargs["timeout"] == 123
        assert kwargs["capture_stdout"] is True
        assert kwargs["capture_stderr"] is True
        assert kwargs["capture_limit"] == r2.const_stdout_capture_limit
        return _completed(_stdout(sections, functions))

    monkeypatch.setattr(r2, "run", fake_run)

    a = r2.analyze(
        _so(tmp_path, bytes(range(256)) * 8),
        argv_prefix=("/opt/r2/bin/radare2",),
        timeout=123,
        version="radare2 5.9.0",
    )
    assert a is not None
    assert calls == [[
        "/opt/r2/bin/radare2", "-q", "-2", "-c", "aa", "-c", "iSj",
        "-c", "aflj", "-c", "q", str(tmp_path / "lib.so"),
    ]]
    assert a.version == "radare2 5.9.0"
    assert len(a.sections) == 1
    sec = a.sections[0]
    assert sec.name == ".text" and sec.paddr == 0 and sec.vaddr == 0x1000
    assert sec.entropy == 8.0
    assert len(a.functions) == 1 and a.functions[0].vaddr == 0x1100
    assert a.total_function_count == 1
    assert a.functions_truncated is False


def test_analyze_uses_addr_when_offset_absent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(r2, "run", lambda *args, **kwargs: _completed(_stdout(
        [], [{"name": "sym.main", "addr": 0x1200, "size": 16, "nbbs": 1}],
    )))
    a = r2.analyze(_so(tmp_path))
    assert a is not None
    assert a.functions[0].vaddr == 0x1200


def test_analyze_truncates_stored_functions(tmp_path: Path, monkeypatch) -> None:
    functions = [
        {"name": "sym.a", "offset": 0x1000, "size": 8, "nbbs": 1},
        {"name": "sym.b", "offset": 0x2000, "size": 8, "nbbs": 1},
    ]
    monkeypatch.setattr(r2, "run", lambda *args, **kwargs: _completed(_stdout([], functions)))
    a = r2.analyze(_so(tmp_path), max_functions=1)
    assert a is not None
    assert len(a.functions) == 1
    assert a.total_function_count == 2
    assert a.functions_truncated is True


# --- fail-soft ---------------------------------------------------------------

def test_analyze_skips_oversized(tmp_path: Path, monkeypatch) -> None:
    called: list[int] = []
    monkeypatch.setattr(r2, "run", lambda *args, **kwargs: called.append(1))
    assert r2.analyze(_so(tmp_path, b"\x00" * 2048), max_bytes=1024) is None
    assert called == []                       # never even opened


def test_analyze_returns_none_on_timeout(tmp_path: Path, monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise ToolTimeoutError("timeout")

    monkeypatch.setattr(r2, "run", fake_run)
    assert r2.analyze(_so(tmp_path)) is None


def test_analyze_returns_none_on_command_error(tmp_path: Path, monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise ToolExecutionError("r2 exploded")

    monkeypatch.setattr(r2, "run", fake_run)
    assert r2.analyze(_so(tmp_path)) is None


@pytest.mark.parametrize("stdout", [
    "",
    "not json",
    "[",
    json.dumps([]),
    json.dumps([]) + "\n[truncated 1 byte(s)]",
])
def test_analyze_returns_none_on_unparseable_output(tmp_path: Path, monkeypatch, stdout: str) -> None:
    monkeypatch.setattr(r2, "run", lambda *args, **kwargs: _completed(stdout))
    assert r2.analyze(_so(tmp_path)) is None


def test_analyze_tolerates_empty_results(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(r2, "run", lambda *args, **kwargs: _completed(_stdout([], [])))
    a = r2.analyze(_so(tmp_path))
    assert a is not None and a.sections == [] and a.functions == []
