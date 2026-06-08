"""`dumpa decompile` — jadx invocation, selector validation, graceful absence."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

import dumpa.commands.decompile as decompile_mod
from dumpa.commands.decompile import decompile
from dumpa.core.errors import DumpaError
from dumpa.core.tools import build_default_registry

_STUB = """#!/bin/sh
case "$1" in
  --version) echo "jadx 1.4.7"; exit 0 ;;
esac
echo "$@" >> "$JADX_STUB_LOG"
exit 0
"""


def _install_stub_jadx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, present: bool = True) -> Path:
    log = tmp_path / "jadx_argv.log"
    monkeypatch.setenv("JADX_STUB_LOG", str(log))
    if present:
        stub = tmp_path / "jadx"
        stub.write_text(_STUB)
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        override = str(stub)
    else:
        override = str(tmp_path / "does-not-exist-jadx")
    monkeypatch.setattr(decompile_mod, "build_default_registry",
                        lambda _paths: build_default_registry({"jadx": override}))
    return log


def _apk(tmp_path: Path) -> Path:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"PK\x03\x04 not a real apk")
    return apk


def test_requires_a_selector(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_jadx(tmp_path, monkeypatch)
    with pytest.raises(DumpaError, match="exactly one selector"):
        decompile(_apk(tmp_path), target_class=None, all_classes=False)


def test_rejects_both_selectors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_jadx(tmp_path, monkeypatch)
    with pytest.raises(DumpaError, match="exactly one selector"):
        decompile(_apk(tmp_path), target_class="a.b.C", all_classes=True)


def test_single_class_argv_and_sidecar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _install_stub_jadx(tmp_path, monkeypatch)
    out = tmp_path / "out"
    decompile(_apk(tmp_path), target_class="com.foo.Bar", out_dir=out)
    argv = log.read_text()
    assert "--single-class com.foo.Bar" in argv
    sidecar = json.loads((out / ".dumpa-decompile.json").read_text())
    assert sidecar["tool"] == "jadx"
    assert sidecar["version"] == "jadx 1.4.7"
    assert sidecar["selector"] == "com.foo.Bar"


def test_all_classes_has_no_single_class(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _install_stub_jadx(tmp_path, monkeypatch)
    out = tmp_path / "out"
    decompile(_apk(tmp_path), all_classes=True, out_dir=out)
    assert "--single-class" not in log.read_text()
    assert (out / ".dumpa-decompile.json").is_file()


def test_rerun_skips_when_sidecar_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _install_stub_jadx(tmp_path, monkeypatch)
    out = tmp_path / "out"
    decompile(_apk(tmp_path), target_class="com.foo.Bar", out_dir=out)
    first = log.read_text()
    decompile(_apk(tmp_path), target_class="com.foo.Bar", out_dir=out)
    assert log.read_text() == first  # second run did not invoke jadx again


def test_missing_jadx_is_graceful(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_jadx(tmp_path, monkeypatch, present=False)
    out = tmp_path / "out"
    # No raise, no output produced.
    decompile(_apk(tmp_path), target_class="com.foo.Bar", out_dir=out)
    assert not out.exists()
