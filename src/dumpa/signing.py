"""Signing-domain runtime checks. Config resolution lives in dumpa.core.config."""

from __future__ import annotations

import datetime
import logging
import re

from dumpa.core.config import (
    SigningConfig,
    const_default_validation_timeout,
    const_env_validation_timeout,
)
from dumpa.core.env import _env_positive_int
from dumpa.core.errors import ToolExecutionError, ToolNotFoundError
from dumpa.core.process import run
from dumpa.core.tools import ToolRegistry

logger = logging.getLogger("dumpa")


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
            timeout=_env_positive_int(const_env_validation_timeout, const_default_validation_timeout),
            capture_stdout=True,
            capture_stderr=True,
        )
    except ToolExecutionError as e:
        raise SystemExit('keystore preflight failed; check keystore path, alias, and password') from e

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
        raise SystemExit(f'keystore certificate expired on {expiry_str}')
    if days_left < 90:
        logger.warning("keystore cert expires in %s days (%s)", days_left, expiry_str)
