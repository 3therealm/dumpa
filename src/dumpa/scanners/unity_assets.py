"""Unity asset scanner: Addressables attribution + serialized-asset parsing.

Two jobs behind the Unity gate (UNITY_SPECS), each a no-op when its inputs are absent:

1. **Addressables attribution** (`_addressables`) — the Addressable Asset System stores its
   content catalog under `assets/aa/`; remote groups embed http(s) load URLs in the
   catalog's internal-id list. This streams those catalogs (bounded, never whole-file) and
   emits an `engine-detail` finding per remote host. Value vs. the endpoint scanner: the
   raw URL is discovered there; this adds *semantic attribution* — labelling hosts as
   Addressables remote content. A bounded URL regex (not a JSON parse) survives catalog
   schema drift across Unity versions.

2. **Serialized-asset parsing** (`_serialized_assets`) — the Phase 6 endpoint scanner only
   sees text-ish files in `extracted/`, so Unity's binary serialized assets (`.assets`
   family + UnityFS AssetBundles) go unread. This parses them via `core/unityasset` (UnityPy),
   dumps TextAsset bodies into `dumps/unity/assets/`, and harvests endpoints + secrets from
   the extracted TextAsset/MonoBehaviour strings — closing the Unity half of the endpoint gap.
   UnityPy is optional: absent -> this half warns and is skipped, Addressables still runs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from dumpa import __version__
from dumpa.core import unityasset
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.rules import apply_bundle, load_builtin
from dumpa.core.unityasset import ExtractedString
from dumpa.core.workspace import Workspace
from dumpa.scanners.endpoint import harvest_urls

logger = logging.getLogger("dumpa")

const_catalog_globs = (
    "assets/aa/**/catalog*.json",
    "assets/aa/catalog*.json",
    "assets/aa/**/catalog*.bundle",
)
const_chunk_size = 1 << 20
const_overlap = 2048
const_max_file_bytes = 512 << 20
const_max_hosts = 100
const_max_samples_per_host = 5

_URL_RE = re.compile(rb"(?:https?|wss?)://[A-Za-z0-9._~:/?#@!$&'()*+,;=%\[\]-]+")
_TRIM = ".,;:'\")]}>"


def _str_list() -> list[str]:
    return []


@dataclass
class _HostHits:
    samples: list[str] = field(default_factory=_str_list)
    file: str = ""
    offset: int = 0


def _host_of(url: str) -> str | None:
    rest = url.split("://", 1)[1] if "://" in url else ""
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    host = host.split("@")[-1].split(":")[0]
    return host.lower() or None


def _catalogs(extracted_dir: Path) -> list[Path]:
    root = extracted_dir.resolve()
    seen: set[Path] = set()
    files: list[Path] = []
    for glob in const_catalog_globs:
        for path in sorted(extracted_dir.glob(glob)):
            if path.is_file() and path.resolve().is_relative_to(root) and path not in seen:
                seen.add(path)
                files.append(path)
    return files


def _record(hosts: dict[str, _HostHits], raw: bytes, offset: int, rel: str) -> None:
    url = raw.decode("latin-1").rstrip(_TRIM)
    host = _host_of(url)
    if host is None:
        return
    hit = hosts.get(host)
    if hit is None:
        if len(hosts) >= const_max_hosts:
            return
        hit = _HostHits(file=rel, offset=offset)
        hosts[host] = hit
    if url not in hit.samples and len(hit.samples) < const_max_samples_per_host:
        hit.samples.append(url)


def _scan_file(path: Path, rel: str, hosts: dict[str, _HostHits]) -> None:
    with path.open("rb") as f:
        tail = b""
        base = 0
        while True:
            chunk = f.read(const_chunk_size)
            if not chunk:
                break
            window = tail + chunk
            window_start = base - len(tail)
            for m in _URL_RE.finditer(window):
                if m.end() == len(window):
                    continue  # possibly truncated at the chunk edge; re-caught next window
                _record(hosts, m.group(), window_start + m.start(), rel)
            base += len(chunk)
            tail = window[-const_overlap:]
        if tail:
            window_start = base - len(tail)
            for m in _URL_RE.finditer(tail):
                _record(hosts, m.group(), window_start + m.start(), rel)


def _addressables(ws: Workspace) -> list[Finding]:
    """Attribute Addressables remote content endpoints (no-op without a catalog)."""
    if not ws.extracted_dir.is_dir():
        return []
    catalogs = _catalogs(ws.extracted_dir)
    if not catalogs:
        return []  # not using Addressables remote content

    hosts: dict[str, _HostHits] = {}
    for path in catalogs:
        if len(hosts) >= const_max_hosts:
            break
        try:
            if path.stat().st_size > const_max_file_bytes:
                continue
            _scan_file(path, path.relative_to(ws.extracted_dir).as_posix(), hosts)
        except OSError:
            logger.debug("addressables scan: cannot read %s", path, exc_info=True)

    findings: list[Finding] = []
    for host, hit in sorted(hosts.items()):
        evidence = [Evidence(description=f"Addressables remote URL {url}", snippet=url, tool="unity")
                    for url in hit.samples]
        findings.append(Finding(
            kind="engine-detail", subject=f"Addressables remote content: {host}",
            confidence=Confidence.MEDIUM, state=FindingState.REFERENCED, attributes={},
            evidence=evidence,
            locations=[Location(file_path=hit.file, file_offset=hit.offset, domain=host)],
        ))
    return findings


# --- serialized-asset parsing (UnityPy) -------------------------------------

const_sidecar = ".dumpa-unity-assets.json"
const_secrets_bundle = "secrets"

# Serialized containers worth parsing. `**/*.assets` covers resources/sharedassets*.assets;
# `level*` (extensionless) and bundles need their own globs. Over-matching is safe — a
# non-serialized file fails soft in the adapter (no objects -> no strings).
const_container_globs = (
    "**/*.assets",
    "**/*.bundle",
    "assets/**/*.unity3d",
    "assets/bin/Data/level*",
)
const_max_containers = 200
const_max_total_bytes = 1 << 30          # aggregate input read cap
const_max_container_bytes = 512 << 20    # one container loaded whole by UnityPy
const_max_dump_files = 2000
const_max_dump_total = 256 << 20
const_max_endpoint_hosts = 100


@dataclass
class _Dumped:
    rel: str            # dumps/-relative path of the written TextAsset
    container: str
    asset_name: str
    path_id: int
    sha256: str
    size: int


def _locate(extracted_dir: Path) -> list[Path]:
    """Find Unity serialized containers under extracted/, deduped + traversal-guarded."""
    root = extracted_dir.resolve()
    seen: set[Path] = set()
    files: list[Path] = []
    for glob in const_container_globs:
        for path in sorted(extracted_dir.glob(glob)):
            if path.is_file() and path.resolve().is_relative_to(root) and path not in seen:
                seen.add(path)
                files.append(path)
    return files


_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_name(asset_name: str, path_id: int) -> str:
    """Collision-safe dump filename: <sanitized-name>__<path_id>.txt.

    The `.txt` suffix is deliberate: TextAsset bodies are text by nature, and it makes the
    dumped file eligible for the secrets bundle's text-file targets (which exclude
    extensionless files) and easy to grep.
    """
    base = _UNSAFE.sub("_", asset_name).strip("_") or "asset"
    return f"{base[:80]}__{path_id}.txt"


def _dump_textassets(ws: Workspace, strings: list[ExtractedString]
                     ) -> tuple[list[_Dumped], dict[int, str]]:
    """Write each TextAsset body to dumps/unity/assets/; return (dumped, path_id->rel).

    Bounded by file count + total bytes; logs (never silently) when a cap truncates output.
    """
    out_dir = ws.dumps_dir / unityasset.const_textasset_subdir
    dumped: list[_Dumped] = []
    by_pathid: dict[int, str] = {}
    total = 0
    capped = False
    for es in strings:
        if es.raw is None:
            continue  # MonoBehaviour field strings are not dumped
        if len(dumped) >= const_max_dump_files or total + len(es.raw) > const_max_dump_total:
            capped = True
            break
        name = _safe_name(es.asset_name, es.path_id)
        path = out_dir / name
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            path.write_bytes(es.raw)
        except OSError:
            logger.warning("unity_assets: cannot write TextAsset dump %s", path, exc_info=True)
            continue
        rel = f"dumps/{path.relative_to(ws.dumps_dir).as_posix()}"
        digest = hashlib.sha256(es.raw).hexdigest()
        dumped.append(_Dumped(rel=rel, container=es.container, asset_name=es.asset_name,
                              path_id=es.path_id, sha256=digest, size=len(es.raw)))
        by_pathid[es.path_id] = rel
        total += len(es.raw)
    if capped:
        logger.warning("unity_assets: TextAsset dump cap reached (%d files / %d bytes); "
                       "remaining assets not written", const_max_dump_files, const_max_dump_total)
    return dumped, by_pathid


def _endpoint_findings(strings: list[ExtractedString], by_pathid: dict[int, str]) -> list[Finding]:
    """Harvest endpoint URLs from extracted Unity strings (flows through the shared tail)."""
    hosts: dict[str, tuple[str, str, ExtractedString]] = {}
    for es in strings:
        if len(hosts) >= const_max_endpoint_hosts:
            break
        data = es.raw if es.raw is not None else es.text.encode("utf-8", "replace")
        for host, url in harvest_urls(data):
            if host not in hosts and len(hosts) < const_max_endpoint_hosts:
                loc_file = by_pathid.get(es.path_id, es.container)
                hosts[host] = (url, loc_file, es)
    out: list[Finding] = []
    for host, (url, loc_file, es) in sorted(hosts.items()):
        out.append(Finding(
            kind="endpoint", subject=host, confidence=Confidence.LOW,
            state=FindingState.PRESENT,
            attributes={"unity_asset": es.asset_name, "unity_class": es.class_name,
                        "unity_path_id": str(es.path_id)},
            evidence=[Evidence(description=f"URL {url} in Unity {es.class_name} '{es.asset_name}'",
                               snippet=url, tool="unity")],
            locations=[Location(file_path=loc_file, domain=host)]))
    return out


def _secret_findings(ws: Workspace) -> list[Finding]:
    """Run the secrets bundle over dumped TextAssets (secret.scan only walks extracted/)."""
    dump_dir = ws.dumps_dir / unityasset.const_textasset_subdir
    if not dump_dir.is_dir():
        return []
    findings = apply_bundle(load_builtin(const_secrets_bundle), dump_dir)
    prefix = f"dumps/{unityasset.const_textasset_subdir}"
    out: list[Finding] = []
    for f in findings:
        locs = [replace(loc, file_path=f"{prefix}/{loc.file_path}") if loc.file_path else loc
                for loc in f.locations]
        out.append(replace(f, locations=locs))
    return out


def _summary_finding(parsed: list[tuple[str, int]], dumped: list[_Dumped]) -> Finding:
    sample = [Location(file_path=rel) for rel, _ in parsed[:5]]
    return Finding(
        kind="engine-detail",
        subject=f"Unity serialized assets parsed ({len(parsed)} containers, {len(dumped)} TextAssets)",
        confidence=Confidence.LOW, state=FindingState.PRESENT,
        attributes={"containers": str(len(parsed)), "textassets": str(len(dumped))},
        evidence=[Evidence(description="UnityPy serialized-asset parse", tool="unity")],
        locations=sample or [Location(file_path="")])


def _write_sidecar(ws: Workspace, parsed: list[tuple[str, int]], dumped: list[_Dumped]) -> None:
    path = ws.dumps_dir / "unity" / const_sidecar
    payload = {
        "engine": "unity",
        "unitypy_version": unityasset.unitypy_version(),
        "dumpa_version": __version__,
        "containers": [{"rel": rel, "strings": n} for rel, n in parsed],
        "dumped": [{"rel": d.rel, "container": d.container, "asset_name": d.asset_name,
                    "path_id": d.path_id, "sha256": d.sha256, "size": d.size} for d in dumped],
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="UTF-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError:
        logger.warning("could not write unity-assets provenance sidecar", exc_info=True)


def _serialized_assets(ws: Workspace) -> list[Finding]:
    """Parse Unity serialized containers -> dump TextAssets + harvest endpoints/secrets."""
    if not unityasset.available():
        logger.warning("UnityPy not installed; skipping Unity serialized-asset parse "
                       "(install with: pip install dumpa[unity])")
        return []
    if not ws.extracted_dir.is_dir():
        return []
    containers = _locate(ws.extracted_dir)
    if not containers:
        return []

    strings: list[ExtractedString] = []
    parsed: list[tuple[str, int]] = []
    total = 0
    for path in containers[:const_max_containers]:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > const_max_container_bytes:
            logger.warning("unity_assets: skipping oversized container %s (%d bytes)", path, size)
            continue
        if total + size > const_max_total_bytes:
            logger.warning("unity_assets: aggregate input cap reached; remaining containers skipped")
            break
        total += size
        rel = path.relative_to(ws.extracted_dir).as_posix()
        extracted = unityasset.parse_container(path, rel)
        strings.extend(extracted)
        parsed.append((rel, len(extracted)))

    if not parsed:
        return []
    dumped, by_pathid = _dump_textassets(ws, strings)
    findings: list[Finding] = []
    findings += _endpoint_findings(strings, by_pathid)
    findings += _secret_findings(ws)
    findings.append(_summary_finding(parsed, dumped))
    _write_sidecar(ws, parsed, dumped)
    return findings


def scan(ws: Workspace) -> list[Finding]:
    """Addressables attribution + UnityPy serialized-asset parsing (each self-gating)."""
    return _addressables(ws) + _serialized_assets(ws)
