"""Signing-domain runtime checks and preset resolution.

Base config resolution (the [signing] table + DUMPA_* env) lives in
dumpa.core.config; this module turns a `--signing` preset into a concrete
SigningConfig and owns the managed debug keystore.
"""

from __future__ import annotations

import datetime
import logging
import os
import re
from pathlib import Path

from dumpa.core.config import (
    Config,
    SigningConfig,
    const_debug_key_alias,
    const_debug_keystore_password,
    const_default_validation_timeout,
    const_env_debug_key_password,
    const_env_debug_keystore_password,
    const_env_validation_timeout,
    const_signing_presets,
)
from dumpa.core.env import env_positive_int
from dumpa.core.errors import ConfigError, ToolExecutionError, ToolNotFoundError
from dumpa.core.process import run
from dumpa.core.tools import ToolRegistry

logger = logging.getLogger("dumpa")


def resolve_signing(preset: str | None, config: Config, registry: ToolRegistry) -> SigningConfig | None:
    """Turn a `--signing` preset into a concrete SigningConfig (or None for unsigned).

      auto     -> config.signing (custom if [signing]/DUMPA_* set, else unsigned)
      unsigned -> None
      custom   -> config.signing; error if signing is not configured
      debug    -> the managed debug keystore (reused or generated)
    """
    name = (preset or 'auto').lower()
    if name not in const_signing_presets:
        raise ConfigError(
            f"unknown signing preset: {preset!r} (expected {', '.join(const_signing_presets)})"
        )
    if name == 'unsigned':
        return None
    if name == 'auto':
        return config.signing
    if name == 'custom':
        if config.signing is None:
            raise ConfigError(
                "--signing custom requires a [signing] table or DUMPA_KEYSTORE_* environment"
            )
        return config.signing
    return ensure_debug_keystore(registry)


def _managed_debug_keystore_path() -> Path:
    """Location of the dumpa-managed debug keystore under XDG data home."""
    xdg = os.environ.get('XDG_DATA_HOME', '').strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / '.local' / 'share'
    return base / 'dumpa' / 'debug.keystore'


def _generate_debug_keystore(registry: ToolRegistry, keystore: Path) -> None:
    """Create an Android-standard debug keystore via keytool."""
    try:
        tool = registry.resolve('keytool')
    except ToolNotFoundError as e:
        raise ConfigError(
            "--signing debug needs keytool (JDK) to create a debug keystore, and none was found"
        ) from e
    keystore.parent.mkdir(parents=True, exist_ok=True)
    run(
        tool.argv(
            '-genkeypair', '-v',
            '-keystore', str(keystore),
            '-storepass', const_debug_keystore_password,
            '-keypass', const_debug_keystore_password,
            '-alias', const_debug_key_alias,
            '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
            '-dname', 'CN=Android Debug,O=Android,C=US',
        ),
        fail_msg='failed to generate debug keystore',
    )
    logger.info("generated debug keystore at %s", keystore)


def ensure_debug_keystore(registry: ToolRegistry) -> SigningConfig:
    """Return a SigningConfig for debug signing, reusing ~/.android or a managed keystore.

    The Android-standard "android" password is published into process-local env vars
    so apksigner's `env:` form can read it without putting a secret on the cmdline.
    """
    android = Path.home() / '.android' / 'debug.keystore'
    if android.is_file():
        keystore = android
    else:
        keystore = _managed_debug_keystore_path()
        if not keystore.is_file():
            _generate_debug_keystore(registry, keystore)
    os.environ[const_env_debug_keystore_password] = const_debug_keystore_password
    os.environ[const_env_debug_key_password] = const_debug_keystore_password
    return SigningConfig(
        keystore_file=keystore,
        key_alias=const_debug_key_alias,
        keystore_password_env=const_env_debug_keystore_password,
        key_password_env=const_env_debug_key_password,
    )


def preflight_keystore(sign: SigningConfig, registry: ToolRegistry) -> None:
    """If keytool is available, validate the keystore alias and warn on near-expiry certs."""
    try:
        tool = registry.resolve('keytool')
    except ToolNotFoundError:
        return
    try:
        proc = run(
            tool.argv(
                '-list', '-v',
                '-keystore', str(sign.keystore_file),
                '-alias', sign.key_alias,
                '-storepass:env', sign.keystore_password_env,
            ),
            timeout=env_positive_int(const_env_validation_timeout, const_default_validation_timeout),
            capture_stdout=True,
            capture_stderr=True,
        )
    except ToolExecutionError as e:
        raise ToolExecutionError('keystore preflight failed; check keystore path, alias, and password') from e

    m = re.search(r'Valid from:.*?until:\s*(.+)$', proc.stdout or '', re.MULTILINE)
    if not m:
        return
    expiry_str = m.group(1).strip()
    expiry: datetime.datetime | None = None
    # keytool emits locale-dependent dates; %Z may not yield a tz-aware datetime, so we tolerate naive comparison below.
    for fmt in ('%a %b %d %H:%M:%S %Z %Y', '%a %b %d %H:%M:%S %z %Y'):
        try:
            expiry = datetime.datetime.strptime(expiry_str, fmt)  # noqa: DTZ007
            break
        except ValueError:
            continue
    if expiry is None:
        return
    now = datetime.datetime.now(expiry.tzinfo) if expiry.tzinfo else datetime.datetime.now()  # noqa: DTZ005
    days_left = (expiry - now).days
    if days_left < 0:
        raise ConfigError(f'keystore certificate expired on {expiry_str}')
    if days_left < 90:
        logger.warning("keystore cert expires in %s days (%s)", days_left, expiry_str)
