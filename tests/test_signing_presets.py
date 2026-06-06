"""resolve_signing: preset -> SigningConfig | None (debug path not exercised here)."""

from __future__ import annotations

from pathlib import Path

import pytest

from dumpa.core.config import Config, SigningConfig
from dumpa.core.errors import ConfigError
from dumpa.core.tools import build_default_registry
from dumpa.signing import resolve_signing

_REG = build_default_registry()
_SIGN = SigningConfig(keystore_file=Path("/tmp/ks.jks"), key_alias="k")


def test_unsigned_returns_none() -> None:
    assert resolve_signing("unsigned", Config(signing=_SIGN), _REG) is None


def test_auto_uses_config_signing() -> None:
    assert resolve_signing("auto", Config(signing=_SIGN), _REG) is _SIGN
    assert resolve_signing(None, Config(signing=_SIGN), _REG) is _SIGN


def test_auto_unconfigured_is_none() -> None:
    assert resolve_signing("auto", Config(signing=None), _REG) is None


def test_custom_requires_config() -> None:
    assert resolve_signing("custom", Config(signing=_SIGN), _REG) is _SIGN
    with pytest.raises(ConfigError, match="custom requires"):
        resolve_signing("custom", Config(signing=None), _REG)


def test_unknown_preset_raises() -> None:
    with pytest.raises(ConfigError, match="unknown signing preset"):
        resolve_signing("bogus", Config(signing=None), _REG)
