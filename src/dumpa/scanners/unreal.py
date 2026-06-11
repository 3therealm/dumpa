"""Unreal Engine deep-helper scanner: pak/IoStore discovery, extraction, endpoint scan.

Beyond "this is Unreal" (the engine scanner's job), this locates the game's packaged
containers — UE4 `.pak` files and UE5 IoStore `.utoc`/`.ucas` — reports the pak version and
packed-file inventory, extracts the harvestable subset of pak entries into
`dumps/unreal/pak/`, and harvests endpoint URLs from the extracted config/text. A provenance
sidecar records what was found and what was deferred.

The zero-dep boundary is loud and deliberate (see `core.unrealpak` / `core.iostore`):
  * UE4 pak entries that are uncompressed or Zlib/Gzip-compressed AND unencrypted -> extracted.
  * Oodle/LZ4 blocks, AES-encrypted entries/indexes, the UE4.25+ path-hash index, and ALL
    UE5 IoStore chunk data -> detected and reported, never extracted. For a typical shipping
    UE5 title (Oodle + AES) enumeration-without-extraction is the expected result, not a bug.

A caller may supply an AES key (`DUMPA_UNREAL_AES` / `[unreal] aes_key`); its presence is
recorded as provenance but the secret bytes are not persisted. The key is unused — stdlib
has no AES, so decryption awaits a future `dumpa[unreal]` optional extra (mirrors the
`dumpa[unity]`/UnityPy precedent).

Runs only behind the Unreal engine gate (UNREAL_SPECS) and self-gates on a container/native
lib being present, so it is a no-op everywhere else.

Deferred: Oodle/LZ4 decompression, AES decryption, UE4.25+ path-hash index, IoStore extraction.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from dumpa import __version__
from dumpa.core import iostore, unrealpak
from dumpa.core.config import load_config
from dumpa.core.fs import read_bytes_resilient
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace
from dumpa.scanners.endpoint import harvest_urls

logger = logging.getLogger("dumpa")

const_kind = "engine-detail"
const_sidecar = ".dumpa-unreal.json"

_LIB_GLOB = "lib/*/libUE*.so"
_PAK_GLOB = "**/*.pak"
_UTOC_GLOB = "**/*.utoc"
_MAX_SAMPLE = 5

# Text/config resources inside an extracted pak worth scanning for endpoint URLs.
_TEXT_SUFFIXES = frozenset({".ini", ".json", ".txt", ".cfg", ".xml", ".uplugin", ".uproject"})
_MAX_CONFIG_BYTES = 8 << 20
_MAX_CONFIG_HOSTS = 50


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _f(subject: str, confidence: Confidence, state: FindingState,
       description: str, snippet: str, locations: list[Location],
       attributes: dict[str, str] | None = None) -> Finding:
    return Finding(
        kind=const_kind, subject=subject, confidence=confidence, state=state,
        attributes=attributes or {},
        evidence=[Evidence(description=description, snippet=snippet, tool="unreal")],
        locations=locations,
    )


def _write_sidecar(ws: Workspace, payload: dict[str, object]) -> None:
    path = ws.dumps_dir / "unreal" / const_sidecar
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="UTF-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError:
        logger.warning("could not write unreal provenance sidecar", exc_info=True)


def _pak_dump_dir(ws: Workspace, rel: str) -> tuple[Path, str]:
    """Return a collision-resistant dump directory for an extracted/-relative pak path."""
    rel_no_ext = Path(rel).with_suffix("")
    dump_rel = Path("unreal") / "pak" / rel_no_ext
    return ws.dumps_dir / dump_rel, dump_rel.as_posix()


def scan(ws: Workspace) -> list[Finding]:
    """Report Unreal containers and extract the harvestable pak subset (no-op if not Unreal)."""
    ex = ws.extracted_dir
    if not ex.is_dir():
        return []
    libs = sorted(ex.glob(_LIB_GLOB))
    paks = sorted(ex.glob(_PAK_GLOB))
    tocs = sorted(ex.glob(_UTOC_GLOB))
    if not libs and not paks and not tocs:
        return []  # not an Unreal app — leave it to other scanners

    findings: list[Finding] = []
    extracted_dirs: list[Path] = []
    sidecar_paks: list[dict[str, object]] = []
    sidecar_tocs: list[dict[str, object]] = []
    version_reported = False
    config = load_config()

    for p in paks:
        pak = unrealpak.parse_standalone(p)
        rel = _rel(p, ex)
        if pak is None:
            continue
        if not version_reported:
            findings.append(_f(
                f"Unreal Engine pak version {pak.version}", Confidence.HIGH,
                FindingState.PRESENT, f"FPakInfo footer in {rel}", rel,
                [Location(file_path=rel)], {"pak_version": str(pak.version)}))
            version_reported = True

        if unrealpak.is_deferred(pak):
            findings.append(_f(
                f"Unreal pak deferred: {rel}", Confidence.MEDIUM, FindingState.PRESENT,
                pak.deferred_reason or "extraction deferred", rel, [Location(file_path=rel)],
                {"pak_version": str(pak.version), "reason": pak.deferred_reason or ""}))
            sidecar_paks.append({"source": rel, "version": pak.version, "entries": 0,
                                 "extracted": 0, "deferred_reason": pak.deferred_reason})
            continue

        sample = [e.path for e in pak.entries[:_MAX_SAMPLE]]
        findings.append(_f(
            f"Unreal pak: {rel} ({len(pak.entries)} files)", Confidence.HIGH,
            FindingState.PRESENT, "packaged asset container", "; ".join(sample),
            [Location(file_path=rel)], {"file_count": str(len(pak.entries))}))

        out_dir, dump_rel = _pak_dump_dir(ws, rel)
        n = unrealpak.extract(p, pak, out_dir)
        if n:
            extracted_dirs.append(out_dir)
        skipped = sum(1 for e in pak.entries
                      if e.encrypted or e.compression not in ("none", "zlib", "gzip"))
        findings.append(_f(
            f"Unreal pak extracted ({n})", Confidence.HIGH, FindingState.INITIALIZED,
            f"from {rel} into dumps/{dump_rel}/"
            + (f"; {skipped} entries deferred (Oodle/encrypted)" if skipped else ""),
            rel, [], {"extracted": str(n), "deferred_entries": str(skipped)}))
        sidecar_paks.append({"source": rel, "version": pak.version,
                             "entries": len(pak.entries), "extracted": n,
                             "deferred_reason": None})

    for t in tocs:
        toc = iostore.parse_toc(t)
        rel = _rel(t, ex)
        if toc is None:
            continue
        flags = []
        if toc.compressed:
            flags.append("compressed")
        if toc.encrypted:
            flags.append("encrypted")
        findings.append(_f(
            f"Unreal IoStore: {rel} ({toc.entry_count} chunks)", Confidence.MEDIUM,
            FindingState.PRESENT,
            "UE5 IoStore container; chunk extraction deferred (Oodle/AES)",
            ", ".join(flags), [Location(file_path=rel)],
            {"toc_version": str(toc.version), "chunks": str(toc.entry_count),
             "encrypted": str(toc.encrypted), "compressed": str(toc.compressed)}))
        sidecar_tocs.append({"source": rel, "version": toc.version,
                             "chunks": toc.entry_count, "encrypted": toc.encrypted,
                             "compressed": toc.compressed, "extracted": 0})

    findings += _aes_key_finding(config.unreal_aes, paks, tocs)
    findings += _endpoint_findings(extracted_dirs, ws)

    if sidecar_paks or sidecar_tocs:
        aes_key = config.unreal_aes
        _write_sidecar(ws, {
            "engine": "unreal",
            "paks": sidecar_paks,
            "tocs": sidecar_tocs,
            "aes_key_provided": aes_key is not None,
            "aes_key_bytes": len(aes_key) if aes_key is not None else None,
            "dumpa_version": __version__,
        })
    return findings


def _aes_key_finding(aes_key: bytes | None, paks: list[Path], tocs: list[Path]) -> list[Finding]:
    """Surface a caller-supplied AES key as recorded-but-unused (decryption is deferred)."""
    if aes_key is None or (not paks and not tocs):
        return []
    return [_f(
        "Unreal AES key provided (decryption deferred)", Confidence.MEDIUM,
        FindingState.PRESENT,
        "AES key supplied via config; decryption needs the dumpa[unreal] extra (no stdlib AES)",
        "caller-provided", [], {"key_source": "caller-provided"})]


def _endpoint_findings(out_dirs: list[Path], ws: Workspace) -> list[Finding]:
    """Harvest endpoint URLs from text/config resources extracted from the pak(s).

    Mirrors the Godot helper: the main endpoint scanner only sees `extracted/` and never
    reads pak-internal config, so this closes the Unreal half of the engine-config endpoint
    gap. Emits `endpoint`-kind findings (subject = host) that flow through the shared domain
    attribution + purpose enrichment like any other endpoint.
    """
    hosts: dict[str, tuple[str, str]] = {}      # host -> (sample url, rel path)
    for out_dir in out_dirs:
        for path in sorted(out_dir.rglob("*")):
            if len(hosts) >= _MAX_CONFIG_HOSTS:
                break
            if not path.is_file() or path.suffix.lower() not in _TEXT_SUFFIXES:
                continue
            try:
                if path.stat().st_size > _MAX_CONFIG_BYTES:
                    continue
                data = read_bytes_resilient(path)
            except OSError:
                logger.debug("unreal endpoint scan: cannot read %s", path, exc_info=True)
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
            evidence=[Evidence(description=f"URL {url}", snippet=url, tool="unreal")],
            locations=[Location(file_path=rel, domain=host)]))
    return out
