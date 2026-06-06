"""External-tool PATH resolution primitives.

These are the low-level lookups (PATH + Windows `.bat` fallback). The declarative
`ToolRegistry` (version probes, install hints, batch preflight) is layered on top of
these in a later step.
"""

from __future__ import annotations

import functools
import os
import shlex
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from dumpa.core.errors import ToolExecutionError, ToolNotFoundError, ToolTimeoutError
from dumpa.core.process import run


@functools.cache
def resolve_executable(name: str) -> tuple[str, ...] | None:
    """Resolve an executable name to argv prefix; check $PATH then .bat fallback.

    Cached: the lookup hits the filesystem (which/stat) and is invoked many times
    across splits — apktool especially. Cache lifetime = single process run.
    """
    direct = shutil.which(name)
    if direct is not None:
        return (direct,)
    batch = get_path_to_batch(name)
    if batch is not None:
        return (batch,)
    return None


def check_if_executable_exists_in_path(executable: str) -> bool:
    """Return True if executable resolves via shutil.which."""
    return shutil.which(executable) is not None


def get_executable_in_path(executable: str) -> str | None:
    """Return the resolved path for an executable on PATH, or None."""
    return shutil.which(executable)


def get_path_to_batch(batch: str) -> str | None:
    """Find a `<name>.bat` on PATH (Windows fallback for shutil.which gaps)."""
    path_env = os.environ.get('PATH', '')
    if not path_env:
        return None
    name = f'{batch}.bat'
    for path in path_env.split(os.pathsep):
        if not path:
            continue
        candidate = Path(path) / name
        if candidate.is_file():
            return str(candidate)
    return None


# === Tool registry ===========================================================
#
# Declarative layer over the raw resolvers above. Each ToolSpec describes how to
# find one external binary, how to probe its version, and what to tell the user
# when it is missing. The registry is the single source of truth shared by command
# preflight (`require`) and the `doctor` command (`probe_all`).


def _first_line(text: str) -> str | None:
    """Default version parser: first non-empty line, stripped."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


@dataclass(frozen=True)
class ToolSpec:
    """Describes one external tool the toolkit may invoke."""
    name: str                                   # logical name, e.g. "apktool"
    executables: tuple[str, ...]                # PATH candidates, in priority order
    required: bool = True                       # if False, absence does not fail doctor
    version_argv: tuple[str, ...] | None = None  # args to print version; None = skip probe
    version_parse: Callable[[str], str | None] = field(default=_first_line)
    min_version: str | None = None              # reserved; not yet enforced
    install_hint: str = ""


@dataclass(frozen=True)
class ResolvedTool:
    """A successfully located tool: the argv prefix to invoke it, plus version if known."""
    spec: ToolSpec
    argv_prefix: tuple[str, ...]
    version: str | None

    def argv(self, *args: str) -> list[str]:
        """Build a full command line: the resolved prefix followed by args."""
        return [*self.argv_prefix, *args]


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of probing one spec, for diagnostic display."""
    spec: ToolSpec
    found: bool
    argv_prefix: tuple[str, ...] | None
    version: str | None


class ToolRegistry:
    """Holds ToolSpecs and resolves/probes them on demand."""

    def __init__(self, overrides: dict[str, str] | None = None) -> None:
        self._specs: dict[str, ToolSpec] = {}
        # logical tool name -> explicit executable path (from config [tools])
        self._overrides: dict[str, str] = dict(overrides or {})

    def register(self, spec: ToolSpec) -> None:
        self._specs[spec.name] = spec

    def specs(self) -> list[ToolSpec]:
        return list(self._specs.values())

    def _resolve_prefix(self, spec: ToolSpec) -> tuple[str, ...] | None:
        override = self._overrides.get(spec.name)
        if override:
            # A configured command wins; if it cannot be resolved, treat the tool as
            # not found (require/doctor reports it) rather than silently falling back.
            return _resolve_command(override)
        for exe in spec.executables:
            prefix = resolve_executable(exe)
            if prefix is not None:
                return prefix
        return None

    def _probe_version(self, spec: ToolSpec, prefix: tuple[str, ...]) -> str | None:
        if spec.version_argv is None:
            return None
        try:
            proc = run([*prefix, *spec.version_argv], timeout=15,
                       capture_stdout=True, capture_stderr=True)
        except (ToolExecutionError, ToolTimeoutError):
            return None
        return spec.version_parse(f'{proc.stdout}\n{proc.stderr}')

    def resolve(self, name: str) -> ResolvedTool:
        """Locate a registered tool. Raises ToolNotFoundError if absent."""
        spec = self._specs[name]
        prefix = self._resolve_prefix(spec)
        if prefix is None:
            raise ToolNotFoundError(_missing_message([spec]))
        return ResolvedTool(spec, prefix, self._probe_version(spec, prefix))

    def require(self, *names: str) -> None:
        """Ensure all named tools resolve; raise once with a combined hint if any are missing."""
        missing: list[ToolSpec] = []
        for name in names:
            spec = self._specs[name]
            if self._resolve_prefix(spec) is None:
                missing.append(spec)
        if missing:
            raise ToolNotFoundError(_missing_message(missing))

    def probe_all(self) -> list[ProbeResult]:
        """Probe every registered spec; never raises (for diagnostics)."""
        results: list[ProbeResult] = []
        for spec in self._specs.values():
            prefix = self._resolve_prefix(spec)
            if prefix is None:
                results.append(ProbeResult(spec, False, None, None))
            else:
                results.append(ProbeResult(spec, True, prefix, self._probe_version(spec, prefix)))
        return results


def _resolve_command(command: str) -> tuple[str, ...] | None:
    """Resolve a configured tool command (from config [tools]) into an argv prefix.

    Accepts any of:
      - a full path to an executable file:   "/opt/Il2CppInspector/Il2CppInspector"
      - a bare command name resolved on PATH: "il2cpp-dumper"
      - a command with fixed leading args:    "dotnet /opt/Il2CppDumper.dll"
    Returns None if the command's head cannot be resolved.
    """
    parts = shlex.split(command)
    if not parts:
        return None
    head, *rest = parts
    if Path(head).is_file():
        prefix: tuple[str, ...] = (head,)
    else:
        resolved = resolve_executable(head)
        if resolved is None:
            return None
        prefix = resolved
    return (*prefix, *rest)


def _missing_message(specs: list[ToolSpec]) -> str:
    parts = []
    for s in specs:
        candidates = ' / '.join(s.executables)
        hint = f' — {s.install_hint}' if s.install_hint else ''
        parts.append(f'{candidates}{hint}')
    return 'required tool(s) not found in PATH: ' + '; '.join(parts)


# Built-in catalog. Tools the convert pipeline needs are `required`; opportunistic
# tools (aapt for badging, keytool for keystore preflight, apksigner only when
# signing) are registered non-required so a bare `doctor` does not flag them.
# il2cpp engines + dotnet are registered when those commands land.
_DEFAULT_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec('apktool', ('apktool',), required=True, version_argv=('--version',),
             install_hint='install via apt/brew or from https://apktool.org'),
    ToolSpec('zipalign', ('zipalign',), required=True,
             install_hint='Android SDK build-tools; add the build-tools dir to PATH'),
    ToolSpec('apksigner', ('apksigner',), required=False,
             install_hint='Android SDK build-tools; required only when signing'),
    ToolSpec('aapt', ('aapt2', 'aapt'), required=False,
             install_hint='Android SDK build-tools; used for output validation'),
    ToolSpec('keytool', ('keytool',), required=False,
             install_hint='part of the JDK; used for keystore preflight'),
    # il2cpp engines: required only by `dump-il2cpp`, so non-required for a bare doctor.
    ToolSpec('il2cppdumper', ('il2cpp-dumper', 'Il2CppDumper', 'il2cppdumper'), required=False,
             install_hint='Il2CppDumper CLI on PATH, or set [tools] il2cppdumper = "<path>" (needs .NET)'),
    ToolSpec('il2cppinspector', ('Il2CppInspector', 'il2cppinspector'), required=False,
             install_hint='Il2CppInspector CLI on PATH, or set [tools] il2cppinspector = "<path>" (needs .NET)'),
)


def build_default_registry(tool_paths: dict[str, str] | None = None) -> ToolRegistry:
    """Construct a registry populated with the toolkit's known external tools.

    `tool_paths` (from config [tools]) overrides PATH resolution per logical name.
    """
    reg = ToolRegistry(overrides=tool_paths)
    for spec in _DEFAULT_SPECS:
        reg.register(spec)
    return reg
