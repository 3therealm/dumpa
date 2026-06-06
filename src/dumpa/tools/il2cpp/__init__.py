"""il2cpp dumping: engine abstraction, input discovery, and engine factory.

A Unity il2cpp build ships native code in lib/<abi>/libil2cpp.so plus the metadata
blob assets/bin/Data/Managed/Metadata/global-metadata.dat. An engine wraps an
external tool (Il2CppDumper / Il2CppInspector) that turns those two into C# stubs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from dumpa.core.errors import DumpaError
from dumpa.core.tools import ResolvedTool

logger = logging.getLogger("dumpa")

def _empty_artifacts() -> dict[str, Path]:
    """Typed default factory for the artifacts map (keeps inference concrete)."""
    return {}


_METADATA_NAME = 'global-metadata.dat'
_BINARY_NAME = 'libil2cpp.so'
# Preference when an apk ships multiple ABIs and the user did not pin one.
_ARCH_PREFERENCE = ('arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86')


@dataclass(frozen=True)
class Il2CppInputs:
    """The two files an il2cpp engine consumes, for one ABI."""
    binary: Path
    metadata: Path
    arch: str


@dataclass(frozen=True)
class Il2CppResult:
    """What an engine produced."""
    engine: str
    out_dir: Path
    artifacts: dict[str, Path] = field(default_factory=_empty_artifacts)


class Il2CppEngine(Protocol):
    """An il2cpp dumping backend wrapping one external tool."""
    name: str
    tool_name: str  # logical registry name to resolve (see core.tools catalog)

    def dump(self, tool: ResolvedTool, inputs: Il2CppInputs, out_dir: Path) -> Il2CppResult: ...


def find_il2cpp_inputs(extracted_dir: Path, arch: str | None = None) -> list[Il2CppInputs]:
    """Locate libil2cpp.so (per ABI) + global-metadata.dat under a raw-extracted apk.

    Returns one entry per ABI found. Empty if either piece is absent. If `arch` is
    given, results are filtered to that ABI.
    """
    metas = sorted(extracted_dir.rglob(_METADATA_NAME))
    if not metas:
        return []
    metadata = metas[0]

    found: list[Il2CppInputs] = []
    lib_root = extracted_dir / 'lib'
    if lib_root.is_dir():
        for abi_dir in sorted(lib_root.iterdir()):
            binary = abi_dir / _BINARY_NAME
            if abi_dir.is_dir() and binary.is_file():
                found.append(Il2CppInputs(binary=binary, metadata=metadata, arch=abi_dir.name))
    if not found:
        # Non-standard layout: take any libil2cpp.so, label by parent dir name.
        for binary in sorted(extracted_dir.rglob(_BINARY_NAME)):
            found.append(Il2CppInputs(binary=binary, metadata=metadata, arch=binary.parent.name))

    if arch is not None:
        found = [i for i in found if i.arch == arch]
    return found


def select_inputs(inputs: list[Il2CppInputs]) -> Il2CppInputs:
    """Pick one ABI by preference order, falling back to the first discovered."""
    by_arch = {i.arch: i for i in inputs}
    for a in _ARCH_PREFERENCE:
        if a in by_arch:
            return by_arch[a]
    return inputs[0]


def get_engine(name: str) -> Il2CppEngine:
    """Return the engine instance for a name ('dumper' | 'inspector')."""
    # Imported lazily to avoid a package-import cycle (engines import from this module).
    from dumpa.tools.il2cpp.dumper import Il2CppDumperEngine
    from dumpa.tools.il2cpp.inspector import Il2CppInspectorEngine

    engines: dict[str, Il2CppEngine] = {
        'dumper': Il2CppDumperEngine(),
        'inspector': Il2CppInspectorEngine(),
    }
    if name not in engines:
        raise DumpaError(f"unknown il2cpp engine: {name!r} (expected 'dumper' or 'inspector')")
    return engines[name]
