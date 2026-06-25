"""Subprocess runner behavior."""

from __future__ import annotations

import subprocess

from dumpa.core import process


def test_run_closes_child_stdin(monkeypatch) -> None:
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(process.subprocess, "run", fake_run)

    process.run(["tool"])

    assert seen["stdin"] == subprocess.DEVNULL
