"""core.fs: transient-OS-error retry + resilient open."""

from __future__ import annotations

import errno
from pathlib import Path

import pytest

from dumpa.core import fs


def test_retry_recovers_after_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fs.time, "sleep", lambda _s: None)
    calls = {"n": 0}

    def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 2:
            raise OSError(errno.EMFILE, "too many open files")
        return "ok"

    assert fs.retry_on_transient(flaky, attempts=3) == "ok"
    assert calls["n"] == 2


def test_retry_reraises_non_transient() -> None:
    def denied() -> None:
        raise OSError(errno.EACCES, "permission denied")

    with pytest.raises(OSError) as exc:
        fs.retry_on_transient(denied, attempts=3, base_delay=0)
    assert exc.value.errno == errno.EACCES


def test_retry_exhausts_then_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fs.time, "sleep", lambda _s: None)
    calls = {"n": 0}

    def always() -> None:
        calls["n"] += 1
        raise OSError(errno.ENFILE, "file table overflow")

    with pytest.raises(OSError):
        fs.retry_on_transient(always, attempts=2)
    assert calls["n"] == 2                       # tried exactly `attempts` times


def test_missing_file_is_not_transient() -> None:
    assert not fs.is_transient_oserror(OSError(errno.ENOENT, "no such file"))
    assert fs.is_transient_oserror(OSError(errno.EMFILE, "emfile"))


def test_open_resilient_retries_then_reads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fs.time, "sleep", lambda _s: None)
    target = tmp_path / "data.bin"
    target.write_bytes(b"payload")
    real_open = Path.open
    state = {"failed": False}

    def flaky_open(self: Path, *a: object, **k: object):  # noqa: ANN401
        if self.name == "data.bin" and not state["failed"]:
            state["failed"] = True
            raise OSError(errno.EMFILE, "too many open files")
        return real_open(self, *a, **k)

    monkeypatch.setattr(Path, "open", flaky_open)
    with fs.open_resilient(target) as f:
        assert f.read() == b"payload"
    assert state["failed"]                        # the first open really did fault
