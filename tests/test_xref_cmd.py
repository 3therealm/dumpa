"""`dumpa xref` command glue: list, query, json, persistence — pipeline stubbed."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

import dumpa.commands.xref as xref_mod
from dumpa.commands.xref import xref
from dumpa.core.errors import DumpaError
from dumpa.core.report import AppFacts, Report
from dumpa.core.workspace import Workspace


def _make_ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path)
    ws.native_dir.mkdir(parents=True, exist_ok=True)
    ws.dex_dir.mkdir(parents=True, exist_ok=True)
    (ws.native_dir / "arm64-v8a__libfoo.so.json").write_text(json.dumps({
        "abi": "arm64-v8a", "lib": "libfoo.so",
        "exports": [{"name": "Java_com_foo_Bar_init", "rva": 16},
                    {"name": "lonely_export", "rva": 32}],
        "imports": [],
    }), encoding="UTF-8")
    (ws.dex_dir / "classes.dex.json").write_text(json.dumps({
        "dex": "classes.dex", "version": 35,
        "classes": [{"name": "com.foo.Bar", "superclass": None, "methods": [], "fields": []}],
    }), encoding="UTF-8")
    return ws


@pytest.fixture()
def stub_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Workspace:
    ws = _make_ws(tmp_path)
    report = Report(dumpa_version="0.1.0", created="t", input_path="/x.apk",
                    facts=AppFacts(input_sha256="a" * 64, input_size=1), findings=[])

    @contextmanager
    def _fake(_workspace: Path) -> Iterator[tuple[Workspace, Report]]:
        yield ws, report

    monkeypatch.setattr(xref_mod, "open_for_diff", _fake)
    return ws


def test_list_builds_and_persists(stub_open: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    xref(stub_open.root)
    out = capsys.readouterr().out
    assert "com.foo.Bar" in out
    assert stub_open.xref_sidecar.is_file()


def test_min_layers_filters(stub_open: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    xref(stub_open.root, min_layers=3)
    assert "com.foo.Bar" not in capsys.readouterr().out


def test_query_found(stub_open: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    xref(stub_open.root, entity="lonely_export")
    out = capsys.readouterr().out
    assert "[symbol] lonely_export" in out
    assert "native:" in out


def test_query_not_found_raises(stub_open: Workspace) -> None:
    with pytest.raises(DumpaError, match="not found"):
        xref(stub_open.root, entity="does.not.exist")


def test_json_output(stub_open: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    xref(stub_open.root, json_=True)
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert any(e["key"] == "com.foo.Bar" for e in payload["entities"])


def test_cache_reused(stub_open: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    xref(stub_open.root)
    capsys.readouterr()
    # Sentinel the cached artifact; a reuse must NOT overwrite it.
    marker = json.loads(stub_open.xref_sidecar.read_text())
    marker["entities"][0]["display"] = "SENTINEL"
    stub_open.xref_sidecar.write_text(json.dumps(marker))
    xref(stub_open.root)
    assert "SENTINEL" in capsys.readouterr().out


def test_out_writes_file(stub_open: Workspace, tmp_path: Path) -> None:
    dest = tmp_path / "report.txt"
    xref(stub_open.root, out=dest)
    assert dest.is_file() and "com.foo.Bar" in dest.read_text()


def test_analyze_maybe_xref(tmp_path: Path) -> None:
    from dumpa.commands.analyze import _maybe_xref, const_file_report_json
    from dumpa.core.report import to_json

    ws = _make_ws(tmp_path)
    report = Report(dumpa_version="0.1.0", created="t", input_path="/x.apk",
                    facts=AppFacts(input_sha256="a" * 64, input_size=1), findings=[])
    ws.reports_dir.mkdir(parents=True, exist_ok=True)
    (ws.reports_dir / const_file_report_json).write_text(to_json(report), encoding="UTF-8")

    _maybe_xref(ws, enabled=False)
    assert not ws.xref_sidecar.exists()

    _maybe_xref(ws, enabled=True)
    assert ws.xref_sidecar.is_file()
    data = json.loads(ws.xref_sidecar.read_text())
    assert any(e["key"] == "com.foo.Bar" for e in data["entities"])
