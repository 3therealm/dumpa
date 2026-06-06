"""Exception hierarchy for the dumpa toolkit.

`DumpaError` is the canonical base. `XapkToApkError` is kept as a back-compat alias
so the migrated convert pipeline (and any external callers) keep working unchanged.
"""

from __future__ import annotations


class DumpaError(RuntimeError):
    """Base exception for expected toolkit failures."""


# Back-compat alias: legacy convert code raises/catches this name.
XapkToApkError = DumpaError


class ToolNotFoundError(DumpaError):
    """Raised when a required external tool is missing or fails its version check."""


class ToolExecutionError(DumpaError):
    """Raised when an external tool exits unsuccessfully."""


class ToolTimeoutError(ToolExecutionError):
    """Raised when an external tool exceeds its timeout."""


class UnsafeArchiveError(DumpaError):
    """Raised when an archive contains unsafe or excessive entries."""


class ManifestError(DumpaError):
    """Raised when a manifest is missing or malformed."""


class ConfigError(DumpaError):
    """Raised when configuration (TOML or environment) is malformed or incomplete."""
