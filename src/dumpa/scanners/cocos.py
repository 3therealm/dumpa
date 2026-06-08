"""Cocos2d-x deep-helper scanner: script bundles, XXTEA key, decryption.

Beyond "this is Cocos2d-x" (the engine scanner's job), this reports the scripting
runtime (JS vs Lua), the engine version, the compiled/encrypted script bundles
(`*.jsc` / `*.luac`), and — when the XXTEA key can be recovered from the native
library — decrypts those bundles into readable JS/Lua under `dumps/cocos/`.

Key recovery is heuristic and confirmation-gated: candidate strings are harvested only
from a window around the `setXXTEAKeyAndSign` marker in `libcocos2d*.so`, then each is
trial-decrypted against a real bundle and accepted only if the output sniffs as Lua
bytecode or printable source. If nothing confirms, bundles are reported as encrypted and
nothing is written — never a guess. The key *source* (file:offset) is logged as evidence;
the key bytes live only in the on-disk provenance sidecar, never in the report.

Decryption is gated to assets of an app you own or are authorized to inspect, per the
roadmap policy. Runs only behind the Cocos2d-x engine gate (COCOS_SPECS).

Deferred: non-XXTEA cocos ciphers; a caller-provided `--key` path.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from dumpa import __version__
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace
from dumpa.core.xxtea import decrypt

logger = logging.getLogger("dumpa")

const_kind = "engine-detail"
const_sidecar = ".dumpa-cocos.json"

_LIB_GLOBS = ("lib/*/libcocos2d*.so",)
_JS_LIB = "libcocos2djs"
_LUA_LIB = "libcocos2dlua"
_BUNDLE_GLOBS = ("assets/**/*.jsc", "assets/**/*.luac")

_VERSION_RE = re.compile(rb"cocos2d-x[ _-]?v?(\d+\.\d+(?:\.\d+)?)")
_KEY_MARKER = b"setXXTEAKeyAndSign"
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,64}")
_KEY_WINDOW = 1024          # bytes scanned either side of the marker for candidate strings
_MAX_KEY_CANDIDATES = 256
_MAX_SIGN_LEN = 16          # the sign prefix is at most this many bytes
_LUA_MAGICS = (b"\x1bLua", b"\x1bLJ")   # luac / luajit bytecode
_PRINTABLE = frozenset(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}
_SNIFF_BYTES = 256
_MAX_BUNDLE_BYTES = 64 << 20    # a single script bundle over this is implausible — skip


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _libs(ex: Path) -> list[Path]:
    out: list[Path] = []
    for g in _LIB_GLOBS:
        out.extend(ex.glob(g))
    return sorted(out)


def _bundles(ex: Path) -> list[Path]:
    out: list[Path] = []
    for g in _BUNDLE_GLOBS:
        out.extend(ex.glob(g))
    return sorted(out)


def _scripting(libs: list[Path]) -> tuple[str, Path] | None:
    for lib in libs:
        if _JS_LIB in lib.name:
            return ("JavaScript", lib)
    for lib in libs:
        if _LUA_LIB in lib.name:
            return ("Lua", lib)
    return None


def _version(libs: list[Path]) -> tuple[str, str] | None:
    """Return (version, lib_name) from a cocos2d-x version string in the native lib."""
    for lib in libs:
        try:
            data = lib.read_bytes()
        except OSError:
            continue
        m = _VERSION_RE.search(data)
        if m:
            return (m.group(1).decode("ascii"), lib.name)
    return None


def _candidate_keys(libs: list[Path]) -> list[bytes]:
    """Harvest printable strings near the setXXTEAKeyAndSign marker as key candidates."""
    seen: set[bytes] = set()
    out: list[bytes] = []
    for lib in libs:
        try:
            data = lib.read_bytes()
        except OSError:
            continue
        start = 0
        while True:
            i = data.find(_KEY_MARKER, start)
            if i < 0:
                break
            window = data[max(0, i - _KEY_WINDOW): i + len(_KEY_MARKER) + _KEY_WINDOW]
            for run in _ASCII_RUN.finditer(window):
                cand = run.group()
                if cand not in seen:
                    seen.add(cand)
                    out.append(cand)
                    if len(out) >= _MAX_KEY_CANDIDATES:
                        return out
            start = i + len(_KEY_MARKER)
    return out


def _looks_decoded(data: bytes) -> bool:
    if not data:
        return False
    if data.startswith(_LUA_MAGICS[0]) or data.startswith(_LUA_MAGICS[1]):
        return True
    head = data[:_SNIFF_BYTES]
    printable = sum(1 for b in head if b in _PRINTABLE)
    return printable / len(head) > 0.85


def _confirm_key(blob: bytes, candidates: list[bytes]) -> tuple[bytes, bytes] | None:
    """Trial-decrypt one bundle against each candidate, deriving the sign from the prefix.

    Returns (key, sign) on the first combination whose output sniffs as a real script.
    The sign is whatever prefix precedes the XXTEA payload, so it is brute-forced by
    length rather than guessed from strings.
    """
    for key in candidates:
        for sign_len in range(_MAX_SIGN_LEN + 1):
            out = decrypt(blob[sign_len:], key)
            if out is not None and _looks_decoded(out):
                return (key, blob[:sign_len])
    return None


def _out_name(rel: str) -> str:
    if rel.endswith(".jsc"):
        return rel[:-4] + ".js"
    if rel.endswith(".luac"):
        return rel[:-5] + ".lua"
    return rel + ".txt"


def _write_decrypted(ws: Workspace, rel: str, data: bytes) -> str | None:
    dest = ws.dumps_dir / "cocos" / "decrypted" / _out_name(rel)
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    except OSError:
        logger.warning("could not write decrypted cocos bundle %s", rel, exc_info=True)
        return None
    return dest.relative_to(ws.root).as_posix()


def _write_sidecar(ws: Workspace, payload: dict) -> None:
    path = ws.dumps_dir / "cocos" / const_sidecar
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="UTF-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError:
        logger.warning("could not write cocos provenance sidecar", exc_info=True)


def _f(subject: str, confidence: Confidence, state: FindingState,
       description: str, snippet: str, locations: list[Location],
       attributes: dict | None = None) -> Finding:
    return Finding(
        kind=const_kind, subject=subject, confidence=confidence, state=state,
        attributes=attributes or {},
        evidence=[Evidence(description=description, snippet=snippet, tool="cocos")],
        locations=locations,
    )


def scan(ws: Workspace) -> list[Finding]:
    """Report cocos scripting/version/bundles and decrypt them when the key is found."""
    ex = ws.extracted_dir
    if not ex.is_dir():
        return []
    libs = _libs(ex)
    bundles = _bundles(ex)
    if not libs and not bundles:
        return []  # not a cocos app — leave it to other scanners

    findings: list[Finding] = []

    scripting = _scripting(libs)
    if scripting is not None:
        lang, lib = scripting
        findings.append(_f(
            f"Cocos2d-x scripting: {lang}", Confidence.HIGH, FindingState.PRESENT,
            f"{lib.name} present", _rel(lib, ex), [Location(file_path=_rel(lib, ex))]))

    ver = _version(libs)
    if ver is not None:
        version, lib_name = ver
        findings.append(_f(
            f"Cocos2d-x version {version}", Confidence.MEDIUM, FindingState.PRESENT,
            f"version string in {lib_name}", lib_name, [], {"version": version}))

    if not bundles:
        return findings

    findings.append(_f(
        f"Cocos2d-x script bundles ({len(bundles)})", Confidence.HIGH, FindingState.PRESENT,
        "compiled/encrypted *.jsc / *.luac", _rel(bundles[0], ex),
        [Location(file_path=_rel(p, ex)) for p in bundles[:5]],
        {"bundle_count": str(len(bundles))}))

    candidates = _candidate_keys(libs)
    confirmed: tuple[bytes, bytes] | None = None
    probe = next((b for b in bundles if b.stat().st_size <= _MAX_BUNDLE_BYTES), None)
    if candidates and probe is not None:
        try:
            confirmed = _confirm_key(probe.read_bytes(), candidates)
        except OSError:
            confirmed = None

    if confirmed is None:
        findings.append(_f(
            "Cocos2d-x bundles encrypted (no key recovered)", Confidence.MEDIUM,
            FindingState.PRESENT, "XXTEA key not found in native lib; bundles left encrypted",
            _rel(bundles[0], ex), []))
        return findings

    key, sign = confirmed
    key_source = _rel(libs[0], ex) if libs else "assets"
    decrypted: list[str] = []
    for b in bundles:
        if b.stat().st_size > _MAX_BUNDLE_BYTES:
            continue
        try:
            out = decrypt(b.read_bytes()[len(sign):], key)
        except OSError:
            continue
        if out is None:
            continue
        rel = _write_decrypted(ws, _rel(b, ex), out)
        if rel is not None:
            decrypted.append(rel)

    findings.append(_f(
        "Cocos2d-x XXTEA key recovered", Confidence.HIGH, FindingState.INITIALIZED,
        f"key harvested from {key_source}", key_source, [],
        {"key_source": key_source, "sign": sign.decode("latin-1")}))
    findings.append(_f(
        f"Cocos2d-x scripts decrypted ({len(decrypted)})", Confidence.HIGH,
        FindingState.INITIALIZED, "decrypted into dumps/cocos/decrypted/",
        decrypted[0] if decrypted else "", []))

    _write_sidecar(ws, {
        "engine": "cocos2d-x",
        "version": ver[0] if ver else None,
        "scripting": scripting[0] if scripting else None,
        "key_source": key_source,
        "key_hex": key.hex(),
        "sign": sign.decode("latin-1"),
        "bundle_count": len(bundles),
        "decrypted_count": len(decrypted),
        "dumpa_version": __version__,
    })
    return findings
