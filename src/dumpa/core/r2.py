"""radare2 analysis via r2pipe: sections, functions, and per-section entropy.

Optional and fail-soft. If r2pipe (or the radare2 binary) is unavailable, the analysis
times out, or radare2 emits something unparseable, `analyze()` returns None and the
caller skips — it never raises on tool/IO trouble. This is the only module that imports
r2pipe, and the import is lazy so the package loads without the dependency installed.

Analysis depth is `aa` (light) rather than `aaa`: a full analysis on a hundreds-of-MB
`libil2cpp.so` runs for minutes. A per-call watchdog kills the radare2 child process if
the deadline passes.
"""

from __future__ import annotations

import contextlib
import logging
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("dumpa")

const_default_timeout = 300            # seconds; watchdog kills r2 past this
const_default_max_bytes = 512 << 20    # skip libraries larger than this

_ENTROPY_RE = re.compile(r"(\d+(?:\.\d+)?)")


@dataclass(frozen=True)
class R2Section:
    name: str
    vaddr: int          # virtual address (RVA)
    paddr: int          # file offset
    size: int
    perm: str           # e.g. "-r-x"
    entropy: float | None


@dataclass(frozen=True)
class R2Function:
    name: str
    vaddr: int
    size: int
    nbbs: int           # basic-block count


@dataclass(frozen=True)
class R2Analysis:
    version: str | None
    sections: list[R2Section]
    functions: list[R2Function]


def _open_r2pipe(path: Path) -> Any | None:
    """Open an r2pipe session on `path`, or None if r2pipe/radare2 is unavailable."""
    try:
        import r2pipe
    except ImportError:
        logger.warning("r2pipe not installed; skipping radare2 analysis "
                       "(pip install r2pipe to enable it)")
        return None
    try:
        return r2pipe.open(str(path), flags=["-2"])   # -2 silences r2's stderr
    except Exception:  # noqa: BLE001 — r2pipe raises bare Exception when r2 is missing
        logger.warning("could not start radare2 on %s; skipping", path.name, exc_info=True)
        return None


def _kill(pipe: Any) -> None:
    """Best-effort kill of the radare2 child process behind an r2pipe session."""
    proc = getattr(pipe, "process", None)
    if proc is not None:
        with contextlib.suppress(Exception):
            proc.kill()


def _quit(pipe: Any) -> None:
    with contextlib.suppress(Exception):
        pipe.quit()


def parse_entropy(text: str | None) -> float | None:
    """Pull the first number out of radare2's `ph entropy` output, or None."""
    if not text:
        return None
    m = _ENTROPY_RE.search(text)
    if m is None:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _section_entropy(pipe: Any, paddr: int, size: int) -> float | None:
    """Entropy of one section via `ph entropy <size> @ <paddr>`; None on failure."""
    if size <= 0:
        return None
    try:
        out = pipe.cmd(f"ph entropy {size} @ {paddr}")
    except Exception:  # noqa: BLE001 — any r2pipe failure → no entropy for this section
        return None
    return parse_entropy(out)


def _collect(pipe: Any, version: str | None) -> R2Analysis:
    """Run analysis commands against an open pipe and build the result (may raise)."""
    pipe.cmd("aa")
    raw_sections = pipe.cmdj("iSj") or []
    raw_functions = pipe.cmdj("aflj") or []

    sections: list[R2Section] = []
    for s in raw_sections:
        name = s.get("name")
        size = s.get("size") or 0
        if not name:
            continue
        paddr = s.get("paddr", 0)
        sections.append(R2Section(
            name=name, vaddr=s.get("vaddr", 0), paddr=paddr, size=size,
            perm=s.get("perm", ""), entropy=_section_entropy(pipe, paddr, size)))

    functions: list[R2Function] = []
    for f in raw_functions:
        name = f.get("name")
        if not name:
            continue
        functions.append(R2Function(
            name=name, vaddr=f.get("offset", 0), size=f.get("size", 0),
            nbbs=f.get("nbbs", 0)))

    return R2Analysis(version=version, sections=sections, functions=functions)


def analyze(path: Path, *, timeout: int = const_default_timeout,
            max_bytes: int = const_default_max_bytes,
            version: str | None = None) -> R2Analysis | None:
    """Analyze one shared object; None on any tool/timeout/size failure (never raises)."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > max_bytes:
        logger.warning("skipping radare2 on %s: %d bytes exceeds cap %d",
                       path.name, size, max_bytes)
        return None

    pipe = _open_r2pipe(path)
    if pipe is None:
        return None

    box: dict[str, R2Analysis] = {}
    err: list[BaseException] = []

    def work() -> None:
        try:
            box["result"] = _collect(pipe, version)
        except BaseException as exc:   # noqa: BLE001 — isolate the worker thread
            err.append(exc)

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        logger.warning("radare2 analysis of %s exceeded %ds; killing", path.name, timeout)
        _kill(pipe)
        return None
    _quit(pipe)
    if err:
        logger.warning("radare2 analysis of %s failed; skipping", path.name, exc_info=err[0])
        return None
    return box.get("result")
