"""Layered configuration: built-in defaults < dumpa.toml < DUMPA_* environment.

Secrets (keystore/key passwords) are read from the environment ONLY and are never
stored in the TOML file. The TOML file holds the keystore path, alias, and min-sdk;
the environment supplies the passwords and may override any TOML value.

Config file is located in this order: explicit path > $DUMPA_CONFIG > ./dumpa.toml >
$XDG_CONFIG_HOME/dumpa/config.toml. A missing file is fine (defaults apply).

Scope note: only [signing] is surfaced today. [tools] path overrides and [convert]
defaults arrive when the tool registry is constructed inside the command flow.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from dumpa.core.errors import ConfigError

# --- environment variable names (the DUMPA_* surface) -----------------------
const_env_config_path = 'DUMPA_CONFIG'
const_env_keystore_file = 'DUMPA_KEYSTORE_FILE'
const_env_keystore_password = 'DUMPA_KEYSTORE_PASSWORD'
const_env_key_alias = 'DUMPA_KEY_ALIAS'
const_env_key_password = 'DUMPA_KEY_PASSWORD'
const_env_min_sdk_version = 'DUMPA_MIN_SDK_VERSION'
const_env_validation_timeout = 'DUMPA_VALIDATION_TIMEOUT_SECONDS'
const_env_il2cpp_engine = 'DUMPA_IL2CPP_ENGINE'
# [analysis]: dump.cs auto-dump + networked Play genre lookup.
const_env_auto_dump = 'DUMPA_AUTO_DUMP'
const_env_play_lookup = 'DUMPA_PLAY_LOOKUP'
const_env_play_timeout = 'DUMPA_PLAY_TIMEOUT_SECONDS'
const_env_play_cache_ttl_days = 'DUMPA_PLAY_CACHE_TTL_DAYS'
# ASN/country host enrichment: separate opt-in (per-host, rate-limited), default off.
const_env_asn_lookup = 'DUMPA_ASN_LOOKUP'
# Caller-provided Cocos2d-x decryption key (tried before heuristic recovery from the lib).
const_env_cocos_key = 'DUMPA_COCOS_KEY'

const_default_validation_timeout = 300
const_default_il2cpp_engine = 'dumper'
const_default_play_cache_ttl_days = 30
const_il2cpp_engines = ('dumper', 'inspector')
const_config_filename = 'dumpa.toml'

# Signing presets (`--signing`). 'auto' = custom-if-configured-else-unsigned (legacy default).
const_signing_presets = ('auto', 'unsigned', 'custom', 'debug')
const_default_signing_preset = 'auto'
# Debug-keystore secrets. These env vars are set by the debug preset itself (the
# Android-standard "android" password), so apksigner's env: form can read them.
const_env_debug_keystore_password = 'DUMPA_DEBUG_KEYSTORE_PASSWORD'
const_env_debug_key_password = 'DUMPA_DEBUG_KEY_PASSWORD'
const_debug_keystore_password = 'android'
const_debug_key_alias = 'androiddebugkey'


def _empty_str_map() -> dict[str, str]:
    """Typed default factory for str->str config maps (keeps inference concrete)."""
    return {}


@dataclass(frozen=True)
class SigningConfig:
    """Resolved signing parameters. Passwords live in the named env vars, not here."""
    keystore_file: Path
    key_alias: str
    min_sdk_version: int | None = None
    keystore_password_env: str = const_env_keystore_password
    key_password_env: str = const_env_key_password


@dataclass(frozen=True)
class AnalysisConfig:
    """dump.cs auto-dump + Play genre lookup settings (the [analysis] section)."""
    auto_dump: bool = True
    play_lookup: bool = True
    play_timeout: int = const_default_validation_timeout
    play_cache_ttl_days: int = const_default_play_cache_ttl_days
    # Per-host ASN/country enrichment is a separate, default-off opt-in (rate-limited,
    # networked); it reuses play_timeout/play_cache logic only loosely, so it gets its flag.
    asn_lookup: bool = False


@dataclass(frozen=True)
class Config:
    """Top-level resolved configuration."""
    signing: SigningConfig | None = None
    tool_paths: dict[str, str] = field(default_factory=_empty_str_map)
    il2cpp_engine: str = const_default_il2cpp_engine
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    # Caller-supplied Cocos2d-x XXTEA key (decoded bytes), or None. The Cocos scanner
    # tries it before its heuristic native-lib recovery, still trial-decrypt confirmed.
    cocos_key: bytes | None = None


def _find_config_file(explicit_path: Path | None) -> Path | None:
    if explicit_path is not None:
        if not explicit_path.is_file():
            raise ConfigError(f"config file not found: {explicit_path}")
        return explicit_path
    env_path = os.environ.get(const_env_config_path, '').strip()
    if env_path:
        p = Path(env_path).expanduser()
        if not p.is_file():
            raise ConfigError(f"{const_env_config_path} points to a missing file: {p}")
        return p
    cwd_cfg = Path.cwd() / const_config_filename
    if cwd_cfg.is_file():
        return cwd_cfg
    xdg = os.environ.get('XDG_CONFIG_HOME', '').strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / '.config'
    user_cfg = base / 'dumpa' / 'config.toml'
    return user_cfg if user_cfg.is_file() else None


def _load_toml(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        with path.open('rb') as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"failed to read config {path}: {e}") from e


def _section(toml: dict[str, Any], name: str) -> dict[str, Any]:
    sec = toml.get(name)
    if sec is None:
        return {}
    if not isinstance(sec, dict):
        raise ConfigError(f"[{name}] must be a table")
    return cast("dict[str, Any]", sec)


def _positive_int_or_none(raw: object, label: str) -> int | None:
    if raw is None or raw == '':
        return None
    # bool is an int subclass; reject it explicitly. Accept TOML ints and env strings.
    if isinstance(raw, bool):
        raise ConfigError(f"{label} must be a positive integer")
    if isinstance(raw, int):
        val = raw
    elif isinstance(raw, str) and raw.strip().isdigit():
        val = int(raw.strip())
    else:
        raise ConfigError(f"{label} must be a positive integer")
    if val < 1:
        raise ConfigError(f"{label} must be a positive integer")
    return val


def _load_signing(sec: dict[str, Any]) -> SigningConfig | None:
    keystore_raw = os.environ.get(const_env_keystore_file) or sec.get('keystore_file')
    alias = os.environ.get(const_env_key_alias) or sec.get('key_alias')
    ks_pw = os.environ.get(const_env_keystore_password)
    key_pw = os.environ.get(const_env_key_password)

    if not any([keystore_raw, alias, ks_pw, key_pw]):
        return None  # signing not configured -> skip, leave apk unsigned

    missing: list[str] = []
    if not keystore_raw:
        missing.append(f'keystore_file ([signing] or {const_env_keystore_file})')
    if not alias:
        missing.append(f'key_alias ([signing] or {const_env_key_alias})')
    if not ks_pw:
        missing.append(const_env_keystore_password)
    if not key_pw:
        missing.append(const_env_key_password)
    if missing:
        raise ConfigError("signing partially configured; missing: " + ", ".join(missing))

    keystore_file = Path(str(keystore_raw)).expanduser()
    if not keystore_file.is_file():
        raise ConfigError(f"keystore file not found: {keystore_file}")

    min_sdk_raw = os.environ.get(const_env_min_sdk_version) or sec.get('min_sdk_version')
    min_sdk = _positive_int_or_none(min_sdk_raw, const_env_min_sdk_version)

    return SigningConfig(keystore_file=keystore_file, key_alias=str(alias), min_sdk_version=min_sdk)


def _load_tool_paths(sec: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in sec.items():
        if not isinstance(value, str):
            raise ConfigError(f"[tools] {name} must be a string path")
        out[name] = value
    return out


def _bool_setting(env_name: str, sec: dict[str, Any], key: str, default: bool, label: str) -> bool:
    """Resolve a boolean from env (1/0/true/false) over TOML over default."""
    raw: object = os.environ.get(env_name)
    if raw is None or raw == '':
        raw = sec.get(key)
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        low = raw.strip().lower()
        if low in ('1', 'true', 'yes', 'on'):
            return True
        if low in ('0', 'false', 'no', 'off'):
            return False
    raise ConfigError(f"{label} must be a boolean (true/false/1/0)")


def _load_analysis(sec: dict[str, Any]) -> AnalysisConfig:
    timeout = _positive_int_or_none(
        os.environ.get(const_env_play_timeout) or sec.get('play_timeout'), const_env_play_timeout)
    ttl = _positive_int_or_none(
        os.environ.get(const_env_play_cache_ttl_days) or sec.get('play_cache_ttl_days'),
        const_env_play_cache_ttl_days)
    return AnalysisConfig(
        auto_dump=_bool_setting(const_env_auto_dump, sec, 'auto_dump', True, 'auto_dump'),
        play_lookup=_bool_setting(const_env_play_lookup, sec, 'play_lookup', True, 'play_lookup'),
        play_timeout=timeout if timeout is not None else const_default_validation_timeout,
        play_cache_ttl_days=ttl if ttl is not None else const_default_play_cache_ttl_days,
        asn_lookup=_bool_setting(const_env_asn_lookup, sec, 'asn_lookup', False, 'asn_lookup'),
    )


def _decode_key(raw: str) -> bytes:
    """Decode a caller-supplied key: `hex:`/`0x` prefix -> raw bytes, else UTF-8 string.

    XXTEA keys are usually ASCII (matching the native-harvested candidates), so the bare
    form is treated as a string; a `hex:`/`0x` prefix supplies raw key bytes explicitly.
    """
    stripped = raw.strip()
    lowered = stripped.lower()
    if lowered.startswith(('hex:', '0x')):
        hexpart = stripped[stripped.find(':') + 1:] if lowered.startswith('hex:') else stripped[2:]
        try:
            return bytes.fromhex(hexpart)
        except ValueError as e:
            raise ConfigError(f"{const_env_cocos_key} hex value is invalid: {e}") from e
    return stripped.encode('utf-8')


def _load_cocos_key(sec: dict[str, Any]) -> bytes | None:
    raw = os.environ.get(const_env_cocos_key) or sec.get('key')
    if raw is None or raw == '':
        return None
    if not isinstance(raw, str):
        raise ConfigError(f"[cocos] key ({const_env_cocos_key}) must be a string")
    return _decode_key(raw)


def _load_il2cpp_engine(sec: dict[str, Any]) -> str:
    engine = os.environ.get(const_env_il2cpp_engine) or sec.get('engine') or const_default_il2cpp_engine
    if not isinstance(engine, str) or engine not in const_il2cpp_engines:
        raise ConfigError(f"il2cpp engine must be one of {const_il2cpp_engines}")
    return engine


def load_config(explicit_path: Path | None = None) -> Config:
    """Locate and parse configuration, layering env over TOML over defaults."""
    toml = _load_toml(_find_config_file(explicit_path))
    return Config(
        signing=_load_signing(_section(toml, 'signing')),
        tool_paths=_load_tool_paths(_section(toml, 'tools')),
        il2cpp_engine=_load_il2cpp_engine(_section(toml, 'il2cpp')),
        analysis=_load_analysis(_section(toml, 'analysis')),
        cocos_key=_load_cocos_key(_section(toml, 'cocos')),
    )
