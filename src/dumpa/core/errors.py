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


class ResChunkError(DumpaError):
    """Raised when a shared AOSP resource-chunk primitive (string pool, scalar read) is malformed.

    Format-neutral: both the AXML and ARSC parsers translate it at their boundary into
    their own `AxmlError` / `ArscError` so each keeps a single public failure type.
    """


class AxmlError(DumpaError):
    """Raised when binary AndroidManifest.xml (AXML) is malformed or truncated."""


class ArscError(DumpaError):
    """Raised when the binary resource table (`resources.arsc`) is malformed or truncated."""


class ElfError(DumpaError):
    """Raised when an ELF shared object is malformed or truncated."""


class DexError(DumpaError):
    """Raised when a DEX (`classesN.dex`) file is malformed or truncated."""


class ConfigError(DumpaError):
    """Raised when configuration (TOML or environment) is malformed or incomplete."""
