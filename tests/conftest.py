"""Shared test fixtures.

Keeps the suite hermetic: the gametype scanner does a networked Play store lookup by
default, so disable it for every test. Tests that exercise the network path do so
through `core.playstore` directly with stubbed transport, never a live request.
"""

from __future__ import annotations

import pytest

from dumpa.core.config import const_env_play_lookup


@pytest.fixture(autouse=True)
def _no_play_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(const_env_play_lookup, "0")
