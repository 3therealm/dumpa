"""Godot deep-helper scanner: PCK discovery, listing, extraction, config scan.

Beyond "this is Godot" (the engine scanner's job), this finds the game's PCK archive —
standalone `*.pck` or appended to `libgodot*.so` — reports the engine version and packed
file inventory, and extracts the resources into `dumps/godot/pck/` with a provenance
sidecar. Godot 4 (format v2) packs and encrypted directories are detected and reported
but not extracted (deferred). `.gdc` bytecode and `project.godot`/`project.binary` config
presence are reported too.

Runs only behind the Godot engine gate (GODOT_SPECS) and self-gates on a pack/native lib
being present, so it is a no-op everywhere else.

Deferred: Godot 4 encrypted-PCK extraction; `.gdc` -> GDScript-source decompilation.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from dumpa import __version__
from dumpa.core.pck import Pck, extract, find_embedded, parse_at, parse_standalone
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace
from dumpa.scanners.endpoint import harvest_urls

logger = logging.getLogger("dumpa")

const_kind = "engine-detail"
const_sidecar = ".dumpa-godot.json"

_LIB_GLOB = "lib/*/libgodot*.so"
_PCK_GLOB = "**/*.pck"
_CONFIG_NAMES = ("project.binary", "project.godot")
_GDC_GLOB = "**/*.gdc"
_MAX_SAMPLE = 5

# Text/config resources inside an extracted PCK worth scanning for endpoint URLs.
_TEXT_SUFFIXES = frozenset({".godot", ".cfg", ".json", ".gd", ".txt", ".tres", ".tscn",
                            ".import", ".ini", ".xml"})
_MAX_CONFIG_BYTES = 8 << 20
_MAX_CONFIG_HOSTS = 50


@dataclass
class _Pack:
    pck: Pck
    source: Path        # the .pck or .so the pack lives in
    rel: str            # source path relative to extracted/


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _collect(ex: Path) -> list[_Pack]:
    packs: list[_Pack] = []
    for p in sorted(ex.glob(_PCK_GLOB)):
        parsed = parse_standalone(p)
        if parsed is not None:
            packs.append(_Pack(parsed, p, _rel(p, ex)))
    for so in sorted(ex.glob(_LIB_GLOB)):
        start = find_embedded(so)
        if start is None:
            continue
        parsed = parse_at(so, start)
        if parsed is not None:
            packs.append(_Pack(parsed, so, _rel(so, ex)))
    return packs


def _f(subject: str, confidence: Confidence, state: FindingState,
       description: str, snippet: str, locations: list[Location],
       attributes: dict[str, str] | None = None) -> Finding:
    return Finding(
        kind=const_kind, subject=subject, confidence=confidence, state=state,
        attributes=attributes or {},
        evidence=[Evidence(description=description, snippet=snippet, tool="godot")],
        locations=locations,
    )


def _write_sidecar(ws: Workspace, payload: dict[str, object]) -> None:
    path = ws.dumps_dir / "godot" / const_sidecar
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="UTF-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError:
        logger.warning("could not write godot provenance sidecar", exc_info=True)


def _ver_str(v: tuple[int, int, int]) -> str:
    return ".".join(str(n) for n in v)


def scan(ws: Workspace) -> list[Finding]:
    """Report Godot version/PCKs/config and extract packed resources (no-op if not Godot)."""
    ex = ws.extracted_dir
    if not ex.is_dir():
        return []
    libs = sorted(ex.glob(_LIB_GLOB))
    has_pck = any(ex.glob(_PCK_GLOB))
    if not libs and not has_pck:
        return []  # not a Godot app — leave it to other scanners

    findings: list[Finding] = []
    packs = _collect(ex)
    extracted_dirs: list[Path] = []

    if packs:
        version = packs[0].pck.godot_version
        findings.append(_f(
            f"Godot version {_ver_str(version)}", Confidence.HIGH, FindingState.PRESENT,
            f"PCK header in {packs[0].rel}", packs[0].rel, [Location(file_path=packs[0].rel)],
            {"version": _ver_str(version)}))

    sidecar_packs: list[dict[str, object]] = []
    for pk in packs:
        deferred = pk.pck.encrypted or pk.pck.fmt_version >= 2
        if deferred:
            reason = "encrypted directory" if pk.pck.encrypted else "Godot 4 format v2"
            findings.append(_f(
                f"Godot PCK deferred: {pk.rel}", Confidence.MEDIUM, FindingState.PRESENT,
                f"{reason}; extraction not supported in v1", pk.rel,
                [Location(file_path=pk.rel)],
                {"fmt_version": str(pk.pck.fmt_version), "encrypted": str(pk.pck.encrypted)}))
            sidecar_packs.append({"source": pk.rel, "fmt_version": pk.pck.fmt_version,
                                  "encrypted": pk.pck.encrypted, "extracted": 0})
            continue

        sample = [e.path for e in pk.pck.entries[:_MAX_SAMPLE]]
        findings.append(_f(
            f"Godot PCK: {pk.rel} ({len(pk.pck.entries)} files)", Confidence.HIGH,
            FindingState.PRESENT, "packed resource archive", "; ".join(sample),
            [Location(file_path=pk.rel)], {"file_count": str(len(pk.pck.entries))}))

        out_dir = ws.dumps_dir / "godot" / "pck" / Path(pk.rel).stem
        n = extract(pk.source, pk.pck, out_dir)
        extracted_dirs.append(out_dir)
        findings.append(_f(
            f"Godot resources extracted ({n})", Confidence.HIGH, FindingState.INITIALIZED,
            f"from {pk.rel} into dumps/godot/pck/{Path(pk.rel).stem}/", pk.rel, []))
        sidecar_packs.append({"source": pk.rel, "fmt_version": pk.pck.fmt_version,
                              "encrypted": False, "extracted": n})

    findings += _config_findings(ex)
    findings += _endpoint_findings(extracted_dirs, ws)

    if packs:
        _write_sidecar(ws, {
            "engine": "godot",
            "version": _ver_str(packs[0].pck.godot_version),
            "packs": sidecar_packs,
            "dumpa_version": __version__,
        })
    return findings


def _endpoint_findings(out_dirs: list[Path], ws: Workspace) -> list[Finding]:
    """Harvest endpoint URLs from text/config resources in the extracted PCK(s).

    Closes the Godot half of the "engine configs" endpoint gap: the main endpoint scanner
    only sees `extracted/` and so never reads PCK-internal config. Emits `endpoint`-kind
    findings (subject = host) that flow through domain attribution + purpose enrichment + the
    report's Endpoints section like any other endpoint; duplicates are deduped downstream.
    """
    hosts: dict[str, tuple[str, str]] = {}     # host -> (sample url, rel path)
    for out_dir in out_dirs:
        for path in sorted(out_dir.rglob("*")):
            if len(hosts) >= _MAX_CONFIG_HOSTS:
                break
            if not path.is_file() or path.suffix.lower() not in _TEXT_SUFFIXES:
                continue
            try:
                if path.stat().st_size > _MAX_CONFIG_BYTES:
                    continue
                data = path.read_bytes()
            except OSError:
                logger.debug("godot endpoint scan: cannot read %s", path, exc_info=True)
                continue
            rel = f"dumps/{path.relative_to(ws.dumps_dir).as_posix()}"
            for host, url in harvest_urls(data):
                if host not in hosts and len(hosts) < _MAX_CONFIG_HOSTS:
                    hosts[host] = (url, rel)
    out: list[Finding] = []
    for host, (url, rel) in sorted(hosts.items()):
        out.append(Finding(
            kind="endpoint", subject=host, confidence=Confidence.LOW,
            state=FindingState.PRESENT, attributes={},
            evidence=[Evidence(description=f"URL {url}", snippet=url, tool="godot")],
            locations=[Location(file_path=rel, domain=host)]))
    return out


def _config_findings(ex: Path) -> list[Finding]:
    out: list[Finding] = []
    for name in _CONFIG_NAMES:
        hit = next(iter(sorted(ex.glob(f"**/{name}"))), None)
        if hit is not None:
            rel = _rel(hit, ex)
            out.append(_f(
                f"Godot config: {name}", Confidence.MEDIUM, FindingState.PRESENT,
                "engine configuration", rel, [Location(file_path=rel)]))
    gdc = sorted(ex.glob(_GDC_GLOB))
    if gdc:
        out.append(_f(
            f"Godot GDScript bytecode ({len(gdc)} .gdc)", Confidence.LOW, FindingState.PRESENT,
            "compiled GDScript", _rel(gdc[0], ex),
            [Location(file_path=_rel(p, ex)) for p in gdc[:_MAX_SAMPLE]],
            {"gdc_count": str(len(gdc))}))
    return out
