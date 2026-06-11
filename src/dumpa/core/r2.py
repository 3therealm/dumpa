"""radare2 analysis via the bounded CLI runner: sections, functions, and entropy.

Optional and fail-soft. If radare2 is unavailable, times out, emits malformed JSON, or
produces more output than the bounded capture limit, `analyze()` returns None and the
caller skips that library. The resolved tool argv prefix is passed in by callers so
configured tool paths are honored.
"""

from __future__ import annotations

import json
import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dumpa.core.errors import ToolExecutionError, ToolTimeoutError
from dumpa.core.fs import open_resilient
from dumpa.core.process import run

logger = logging.getLogger("dumpa")

const_default_timeout = 300             # seconds
const_default_max_bytes = 512 << 20     # skip libraries larger than this
const_stdout_capture_limit = 64 << 20   # bounded radare2 JSON capture
const_default_max_functions = 50_000    # stored functions in memory/sidecar
const_entropy_chunk = 1 << 20

_ENTROPY_RE = re.compile(r"(\d+(?:\.\d+)?)")
_JSON_DECODER = json.JSONDecoder()
_TRUNCATED_OUTPUT_MARKER = "\n[truncated "


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
    total_function_count: int | None = None
    functions_truncated: bool = False


def parse_entropy(text: str | None) -> float | None:
    """Pull the first valid Shannon entropy value (0..8) out of text, or None."""
    if not text:
        return None
    m = _ENTROPY_RE.search(text)
    if m is None:
        return None
    try:
        entropy = float(m.group(1))
    except ValueError:
        return None
    if not 0.0 <= entropy <= 8.0:
        return None
    return entropy


def _as_int(value: object) -> int:
    if not isinstance(value, int | float | str | bytes | bytearray):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


def _as_str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _next_json_start(text: str, start: int) -> int:
    positions = [p for p in (text.find("[", start), text.find("{", start)) if p >= 0]
    return min(positions) if positions else -1


def _json_docs(text: str) -> list[Any] | None:
    """Decode JSON values from radare2 stdout, tolerating non-JSON log prefixes."""
    if _TRUNCATED_OUTPUT_MARKER in text:
        return None
    docs: list[Any] = []
    index = 0
    while index < len(text):
        start = _next_json_start(text, index)
        if start < 0:
            break
        try:
            doc, index = _JSON_DECODER.raw_decode(text, start)
        except json.JSONDecodeError:
            return None
        docs.append(doc)
    return docs


def _first_two_lists(text: str) -> tuple[list[Any], list[Any]] | None:
    docs = _json_docs(text)
    if docs is None:
        return None
    lists = [doc for doc in docs if isinstance(doc, list)]
    if len(lists) < 2:
        return None
    return lists[0], lists[1]


def _entropy_for_region(path: Path, paddr: int, size: int) -> float | None:
    """Compute Shannon entropy over one file region without loading it all at once."""
    if paddr < 0 or size <= 0:
        return None
    counts = [0] * 256
    total = 0
    try:
        with open_resilient(path) as f:
            f.seek(paddr)
            remaining = size
            while remaining > 0:
                chunk = f.read(min(const_entropy_chunk, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                total += len(chunk)
                for b in chunk:
                    counts[b] += 1
    except OSError:
        return None
    if total == 0:
        return None
    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def _sections(path: Path, raw_sections: list[Any]) -> list[R2Section]:
    sections: list[R2Section] = []
    for raw in raw_sections:
        if not isinstance(raw, dict):
            continue
        name = _as_str(raw.get("name"))
        size = _as_int(raw.get("size"))
        if not name:
            continue
        paddr = _as_int(raw.get("paddr"))
        sections.append(R2Section(
            name=name,
            vaddr=_as_int(raw.get("vaddr")),
            paddr=paddr,
            size=size,
            perm=_as_str(raw.get("perm")),
            entropy=_entropy_for_region(path, paddr, size),
        ))
    return sections


def _functions(raw_functions: list[Any], max_functions: int) -> tuple[list[R2Function], int, bool]:
    total = sum(1 for raw in raw_functions if isinstance(raw, dict) and raw.get("name"))
    functions: list[R2Function] = []
    for raw in raw_functions:
        if len(functions) >= max_functions:
            break
        if not isinstance(raw, dict):
            continue
        name = _as_str(raw.get("name"))
        if not name:
            continue
        functions.append(R2Function(
            name=name,
            vaddr=_as_int(raw.get("offset", raw.get("addr"))),
            size=_as_int(raw.get("size")),
            nbbs=_as_int(raw.get("nbbs")),
        ))
    return functions, total, total > len(functions)


def _collect_from_stdout(path: Path, stdout: str, version: str | None,
                         max_functions: int) -> R2Analysis | None:
    raw = _first_two_lists(stdout)
    if raw is None:
        return None
    raw_sections, raw_functions = raw
    functions, total_functions, truncated = _functions(raw_functions, max_functions)
    return R2Analysis(
        version=version,
        sections=_sections(path, raw_sections),
        functions=functions,
        total_function_count=total_functions,
        functions_truncated=truncated,
    )


def _argv(argv_prefix: tuple[str, ...], path: Path) -> list[str]:
    return [
        *argv_prefix,
        "-q",
        "-2",
        "-c",
        "aa",
        "-c",
        "iSj",
        "-c",
        "aflj",
        "-c",
        "q",
        str(path),
    ]


def analyze(path: Path, *, argv_prefix: tuple[str, ...] = ("radare2",),
            timeout: int = const_default_timeout,
            max_bytes: int = const_default_max_bytes,
            max_functions: int = const_default_max_functions,
            version: str | None = None) -> R2Analysis | None:
    """Analyze one shared object; None on any tool/timeout/size/parse failure."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > max_bytes:
        logger.warning("skipping radare2 on %s: %d bytes exceeds cap %d",
                       path.name, size, max_bytes)
        return None

    try:
        proc = run(
            _argv(argv_prefix, path),
            timeout=timeout,
            capture_stdout=True,
            capture_stderr=True,
            capture_limit=const_stdout_capture_limit,
            quiet=True,
        )
    except (ToolExecutionError, ToolTimeoutError):
        logger.warning("radare2 analysis of %s failed; skipping", path.name, exc_info=True)
        return None

    analysis = _collect_from_stdout(path, proc.stdout, version, max_functions)
    if analysis is None:
        logger.warning("radare2 analysis of %s produced unparseable output; skipping", path.name)
    return analysis
