"""Godot deep-helper scanner: PCK discovery, listing, extraction, config + .gdc scan.

Beyond "this is Godot" (the engine scanner's job), this finds the game's PCK archive —
standalone `*.pck` or appended to `libgodot*.so` — reports the engine version and packed
file inventory, and extracts the resources into `dumps/godot/pck/` with a provenance
sidecar. Format v1 (Godot 3.x) and v2-v4 (Godot 4.x) normal packs extract directly;
encrypted-directory / per-file-encrypted packs extract only when the caller supplies the
AES key (`DUMPA_GODOT_AES` / `[godot] aes_key`, the optional `dumpa[godot]` extra) and are
otherwise reported as deferred. Sparse/delta bundles are detected and deferred.

`.gdc` GDScript bytecode is parsed for its identifier + string-constant pool (`core.gdc`,
not a decompiler) and those strings are mined for endpoints + secrets. `project.godot` /
`project.binary` config presence is reported too.

Runs only behind the Godot engine gate (GODOT_SPECS) and self-gates on a pack/native lib
being present, so it is a no-op everywhere else.

Deferred: Zstd-compressed Godot 4 `.gdc` bodies, `.gdc` -> GDScript-source decompilation,
sparse/delta PCK bundles, and `.gde` encrypted script files.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from dumpa import __version__
from dumpa.core import gdc, unrealcrypto
from dumpa.core.config import const_env_godot_key, load_config
from dumpa.core.errors import ConfigError
from dumpa.core.fs import read_bytes_resilient
from dumpa.core.pck import (
    PACK_FILE_DELTA,
    PACK_FILE_ENCRYPTED,
    PACK_FILE_REMOVAL,
    Pck,
    extract,
    find_embedded,
    parse_at,
    parse_standalone,
)
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.rules import load_builtin, match_content_strings
from dumpa.core.workspace import Workspace
from dumpa.scanners.endpoint import harvest_urls

logger = logging.getLogger("dumpa")

const_kind = "engine-detail"
const_sidecar = ".dumpa-godot.json"
const_secrets_bundle = "secrets"

_LIB_GLOB = "lib/*/libgodot*.so"
_PCK_GLOB = "**/*.pck"
_CONFIG_NAMES = ("project.binary", "project.godot")
_GDC_GLOB = "**/*.gdc"
_MAX_SAMPLE = 5
_MAX_GDC_FILES = 5000
_MAX_GDC_BYTES = 16 << 20
_MAX_GDC_STRINGS_SIDECAR = 200

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


def _collect(ex: Path, key: bytes | None) -> list[_Pack]:
    packs: list[_Pack] = []
    for p in sorted(ex.glob(_PCK_GLOB)):
        parsed = parse_standalone(p, key)
        if parsed is not None:
            packs.append(_Pack(parsed, p, _rel(p, ex)))
    for so in sorted(ex.glob(_LIB_GLOB)):
        start = find_embedded(so)
        if start is None:
            continue
        parsed = parse_at(so, start, key)
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


def _pck_dump_dir(ws: Workspace, rel: str) -> tuple[Path, str]:
    """Return a collision-resistant dump directory for an extracted/-relative pack path."""
    rel_no_ext = Path(rel).with_suffix("")
    dump_rel = Path("godot") / "pck" / rel_no_ext
    return ws.dumps_dir / dump_rel, dump_rel.as_posix()


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

    try:
        key = load_config().godot_key
    except ConfigError as exc:
        # A malformed Godot key must not abort the scan — defer decryption, keep going.
        if const_env_godot_key not in str(exc) and "[godot]" not in str(exc):
            raise
        logger.warning("invalid Godot AES key (%s); decryption deferred", const_env_godot_key)
        key = None
    findings: list[Finding] = []
    packs = _collect(ex, key)
    extracted_dirs: list[Path] = []

    if packs:
        version = packs[0].pck.godot_version
        findings.append(_f(
            f"Godot version {_ver_str(version)}", Confidence.HIGH, FindingState.PRESENT,
            f"PCK header in {packs[0].rel}", packs[0].rel, [Location(file_path=packs[0].rel)],
            {"version": _ver_str(version)}))

    sidecar_packs: list[dict[str, object]] = []
    any_encrypted = False
    for pk in packs:
        any_encrypted = any_encrypted or pk.pck.encrypted
        if pk.pck.deferred_reason is not None:
            findings.append(_f(
                f"Godot PCK deferred: {pk.rel}", Confidence.MEDIUM, FindingState.PRESENT,
                f"{pk.pck.deferred_reason}; not extracted", pk.rel,
                [Location(file_path=pk.rel)],
                {"fmt_version": str(pk.pck.fmt_version), "encrypted": str(pk.pck.encrypted),
                 "reason": pk.pck.deferred_reason}))
            sidecar_packs.append({"source": pk.rel, "fmt_version": pk.pck.fmt_version,
                                  "encrypted": pk.pck.encrypted,
                                  "deferred": pk.pck.deferred_reason, "extracted": 0})
            continue

        enc_entries = sum(1 for e in pk.pck.entries if e.flags & PACK_FILE_ENCRYPTED)
        any_encrypted = any_encrypted or enc_entries > 0

        sample = [e.path for e in pk.pck.entries[:_MAX_SAMPLE]]
        findings.append(_f(
            f"Godot PCK: {pk.rel} ({len(pk.pck.entries)} files)", Confidence.HIGH,
            FindingState.PRESENT, "packed resource archive", "; ".join(sample),
            [Location(file_path=pk.rel)],
            {"file_count": str(len(pk.pck.entries)), "fmt_version": str(pk.pck.fmt_version)}))

        out_dir, dump_rel = _pck_dump_dir(ws, pk.rel)
        n = extract(pk.source, pk.pck, out_dir, key)
        extracted_dirs.append(out_dir)
        findings.append(_f(
            f"Godot resources extracted ({n}/{len(pk.pck.entries)})", Confidence.HIGH,
            FindingState.INITIALIZED, f"from {pk.rel} into dumps/{dump_rel}/", pk.rel, []))
        if enc_entries and n < len(pk.pck.entries):
            have_key = key is not None and unrealcrypto.aes_available()
            reason = ("per-file encrypted (decrypt failed)" if have_key
                      else "per-file encrypted (no key)")
            findings.append(_f(
                f"Godot PCK partially deferred: {pk.rel} ({enc_entries} encrypted entries)",
                Confidence.MEDIUM, FindingState.PRESENT,
                "per-file encrypted entries were skipped", pk.rel,
                [Location(file_path=pk.rel)],
                {"fmt_version": str(pk.pck.fmt_version),
                 "encrypted_entries": str(enc_entries), "reason": reason}))
        delta_entries = sum(1 for e in pk.pck.entries
                            if e.flags & (PACK_FILE_DELTA | PACK_FILE_REMOVAL))
        if delta_entries:
            findings.append(_f(
                f"Godot PCK partially deferred: {pk.rel} ({delta_entries} delta/removal entries)",
                Confidence.MEDIUM, FindingState.PRESENT,
                "delta/removal entries are not extracted", pk.rel,
                [Location(file_path=pk.rel)],
                {"fmt_version": str(pk.pck.fmt_version),
                 "delta_entries": str(delta_entries),
                 "reason": "delta/removal entries unsupported"}))
        sidecar_packs.append({"source": pk.rel, "fmt_version": pk.pck.fmt_version,
                              "encrypted": pk.pck.encrypted,
                              "encrypted_entries": enc_entries,
                              "delta_entries": delta_entries, "extracted": n,
                              "file_count": len(pk.pck.entries)})

    findings += _key_finding(key, any_encrypted)
    findings += _config_findings(ex)
    findings += _gdc_findings(ex, extracted_dirs, ws)
    findings += _endpoint_findings(extracted_dirs, ws)

    if packs:
        _write_sidecar(ws, {
            "engine": "godot",
            "version": _ver_str(packs[0].pck.godot_version),
            "packs": sidecar_packs,
            "key_provided": key is not None,
            "key_bytes": len(key) if key is not None else None,
            "dumpa_version": __version__,
        })
    return findings


def _key_finding(key: bytes | None, any_encrypted: bool) -> list[Finding]:
    """Surface a caller-supplied Godot AES key when there is an encrypted pack to use it on."""
    if key is None or not any_encrypted:
        return []
    if unrealcrypto.aes_available():
        subject = "Godot AES key provided (used for decryption)"
        detail = "AES key supplied via config; used to decrypt the encrypted PCK directory/entries"
    else:
        subject = "Godot AES key provided (decryption deferred)"
        detail = "AES key supplied via config; decryption needs the dumpa[godot] extra"
    return [_f(subject, Confidence.MEDIUM, FindingState.PRESENT,
               detail, "caller-provided", [], {"key_source": "caller-provided"})]


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
                data = read_bytes_resilient(path)
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


def _gdc_findings(ex: Path, extracted_dirs: list[Path], ws: Workspace) -> list[Finding]:
    """Parse `.gdc` token buffers, mine endpoints + secrets from their string pool.

    Scans both loose `.gdc` under `extracted/` and the scripts written into `dumps/godot/pck/`
    when a PCK is unpacked — normal Godot scripts live inside the PCK, so the dump dirs are
    where most `.gdc` actually land.
    """
    gdc_files: list[tuple[Path, str]] = [(p, _rel(p, ex)) for p in sorted(ex.glob(_GDC_GLOB))]
    for d in extracted_dirs:
        gdc_files += [(p, f"dumps/{_rel(p, ws.dumps_dir)}") for p in sorted(d.glob(_GDC_GLOB))]
    if not gdc_files:
        return []
    bundle = load_builtin(const_secrets_bundle)
    secret_rules = [r for r in bundle.rules if r.regex or r.strings]
    findings: list[Finding] = []
    sidecar: dict[str, object] = {}
    versions: set[int] = set()
    total_strings = 0
    compressed = 0
    for path, rel in gdc_files[:_MAX_GDC_FILES]:
        try:
            if path.stat().st_size > _MAX_GDC_BYTES:
                continue
            data = read_bytes_resilient(path)
        except OSError:
            logger.debug("godot .gdc scan: cannot read %s", path, exc_info=True)
            continue
        info = gdc.parse(data)
        if info is None:
            continue
        versions.add(info.version)
        if info.compressed:
            compressed += 1
        strings = [(0, s) for s in info.strings if s]
        total_strings += len(strings)
        sidecar[rel] = {"version": info.version, "godot4": info.godot4,
                        "compressed": info.compressed,
                        "strings": [s for _, s in strings[:_MAX_GDC_STRINGS_SIDECAR]]}
        findings += _gdc_endpoints(strings, rel)
        findings += match_content_strings(secret_rules, bundle, strings, rel)

    ver_str = ",".join(str(v) for v in sorted(versions)) if versions else "unknown"
    findings.append(_f(
        f"Godot GDScript bytecode ({len(gdc_files)} .gdc)", Confidence.LOW,
        FindingState.PRESENT, "compiled GDScript token buffers", gdc_files[0][1],
        [Location(file_path=rel) for _, rel in gdc_files[:_MAX_SAMPLE]],
        {"gdc_count": str(len(gdc_files)), "string_count": str(total_strings),
         "versions": ver_str, "compressed_deferred": str(compressed)}))
    if sidecar:
        _write_gdc_sidecar(ws, sidecar)
    return findings


def _gdc_endpoints(strings: list[tuple[int, str]], rel: str) -> list[Finding]:
    """Harvest URLs out of decoded .gdc strings, one `endpoint` finding per host."""
    hosts: dict[str, str] = {}
    for _off, text in strings:
        for host, url in harvest_urls(text.encode("utf-8", "replace")):
            hosts.setdefault(host, url)
    out: list[Finding] = []
    for host, url in sorted(hosts.items()):
        out.append(Finding(
            kind="endpoint", subject=host, confidence=Confidence.LOW,
            state=FindingState.PRESENT, attributes={},
            evidence=[Evidence(description=f"URL {url}", snippet=url, tool="godot")],
            locations=[Location(file_path=rel, domain=host)]))
    return out


def _write_gdc_sidecar(ws: Workspace, payload: dict[str, object]) -> None:
    path = ws.dumps_dir / "godot" / "gdc" / "strings.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="UTF-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError:
        logger.warning("could not write godot .gdc sidecar", exc_info=True)


def _config_findings(ex: Path) -> list[Finding]:
    out: list[Finding] = []
    for name in _CONFIG_NAMES:
        hit = next(iter(sorted(ex.glob(f"**/{name}"))), None)
        if hit is not None:
            rel = _rel(hit, ex)
            out.append(_f(
                f"Godot config: {name}", Confidence.MEDIUM, FindingState.PRESENT,
                "engine configuration", rel, [Location(file_path=rel)]))
    return out
