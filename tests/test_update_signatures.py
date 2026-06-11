"""update-signatures fetch wrapper."""

from __future__ import annotations

import pytest

from dumpa.commands import update_signatures as update_cmd
from dumpa.core.errors import DumpaError


class _Response:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self.data if size < 0 else self.data[:size]


def test_fetch_rejects_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"{" + b"x" * update_cmd.const_max_fetch_bytes + b"}"
    monkeypatch.setattr(
        update_cmd.urllib.request,
        "urlopen",
        lambda req, timeout: _Response(data),
    )

    with pytest.raises(DumpaError, match="exceeds"):
        update_cmd._fetch("https://example.invalid/trackers")


def test_fetch_maps_invalid_url_to_dumpa_error() -> None:
    with pytest.raises(DumpaError, match="failed to fetch"):
        update_cmd._fetch("://bad-url")
