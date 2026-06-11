"""Unity deep-helper scanner: scripting backend + IL2CPP metadata facts.

Beyond "this is Unity" (the engine scanner's job), this reports:
  - scripting backend: IL2CPP (libil2cpp.so / global-metadata.dat) vs Mono
    (libmono*.so / managed .dll assemblies)
  - IL2CPP metadata version, read from the global-metadata.dat header
  - global-metadata.dat validation (the il2cpp magic 0xFAB11BAF)

It runs only when Unity markers are present, so it is a no-op on non-Unity apps.
"""

from __future__ import annotations

import struct
from pathlib import Path

from dumpa.core.fs import open_resilient
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace

const_kind = "engine-detail"
# global-metadata.dat header: uint32 sanity magic, then int32 version.
const_il2cpp_magic = 0xFAB11BAF
_METADATA_HEADER = struct.Struct("<Ii")


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _metadata_version(path: Path) -> tuple[bool, int | None]:
    """Return (magic_ok, version) from a global-metadata.dat header."""
    try:
        with open_resilient(path) as f:
            head = f.read(_METADATA_HEADER.size)
    except OSError:
        return (False, None)
    if len(head) < _METADATA_HEADER.size:
        return (False, None)
    magic, version = _METADATA_HEADER.unpack(head)
    if magic != const_il2cpp_magic:
        return (False, None)
    return (True, version)


def _finding(subject: str, confidence: Confidence, description: str,
             snippet: str, locations: list[Location]) -> Finding:
    return Finding(
        kind=const_kind, subject=subject, confidence=confidence, state=FindingState.PRESENT,
        evidence=[Evidence(description=description, snippet=snippet, tool="unity")],
        locations=locations,
    )


def scan(ws: Workspace) -> list[Finding]:
    """Report Unity scripting backend and IL2CPP metadata facts (no-op if not Unity)."""
    ex = ws.extracted_dir
    if not ex.is_dir():
        return []

    il2cpp = sorted(ex.glob("lib/*/libil2cpp.so"))
    metas = sorted(ex.glob("**/global-metadata.dat"))
    mono = sorted(ex.glob("lib/*/libmono*.so")) + sorted(ex.glob("assets/bin/Data/Managed/*.dll"))
    if not (il2cpp or metas or mono):
        return []  # not a Unity app — leave it to other scanners

    findings: list[Finding] = []

    if il2cpp or metas:
        marker = (il2cpp or metas)[0]
        findings.append(_finding(
            "Unity scripting backend: IL2CPP", Confidence.HIGH,
            "libil2cpp.so / global-metadata.dat present", _rel(marker, ex),
            [Location(file_path=_rel(p, ex)) for p in (il2cpp or metas)[:5]],
        ))
    else:
        findings.append(_finding(
            "Unity scripting backend: Mono", Confidence.HIGH,
            "Mono runtime / managed assemblies present", _rel(mono[0], ex),
            [Location(file_path=_rel(p, ex)) for p in mono[:5]],
        ))

    if metas:
        meta_path = metas[0]
        rel = _rel(meta_path, ex)
        ok, version = _metadata_version(meta_path)
        if ok and version is not None:
            findings.append(_finding(
                f"IL2CPP metadata version {version}", Confidence.HIGH,
                "global-metadata.dat header parsed", rel, [Location(file_path=rel)],
            ))
        else:
            findings.append(_finding(
                "global-metadata.dat: unrecognized header", Confidence.MEDIUM,
                f"expected il2cpp magic {const_il2cpp_magic:#010x}", rel, [Location(file_path=rel)],
            ))

    return findings
