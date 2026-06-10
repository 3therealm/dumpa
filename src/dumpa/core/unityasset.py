"""UnityPy adapter: extract strings from Unity serialized assets.

The one module that imports UnityPy. Everything else (the `unity_assets` scanner) talks to
this façade in pure dumpa types, so a UnityPy API shift is a one-file fix and the dependency
stays optional. UnityPy is loaded lazily inside the functions that need it, so importing this
module never requires the `unity` extra; callers gate on `available()` first.

`parse_container` turns one `.assets`/UnityFS bundle into a bounded, fail-soft list of
`ExtractedString` — TextAsset bodies (with raw bytes for dumping) and MonoBehaviour string
fields — each tagged with its container, asset name, object path-id, and Unity class. The
heavy lifting (UnityFS LZ4/LZMA decompression, SerializedFile + TypeTree parsing) is UnityPy's;
this file only classifies objects, walks typetrees for string leaves, and enforces bounds.

The UnityPy-touching surface is deliberately a thin shell over pure helpers (`_walk_strings`,
`_coerce_script`, `_class_of`) so the bounds/extraction logic is unit-testable without a real
container, and real end-to-end extraction is exercised by the gitignored golden-apk corpus.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("dumpa")

const_textasset_subdir = "unity/assets"   # under ws.dumps_dir

# Bounds (the scanner passes its own; these are sane fallbacks).
const_max_obj = 5000
const_max_bytes_per_obj = 1 << 20         # truncate one TextAsset body / string field
const_max_strings_per_obj = 64            # cap string leaves walked out of one MonoBehaviour

# Unity classes worth extracting strings from. TextAsset carries config/script bodies;
# MonoBehaviour carries serialized component fields (often URLs/keys in string members).
_TEXTASSET = "TextAsset"
_MONOBEHAVIOUR = "MonoBehaviour"


class UnityPyUnavailable(RuntimeError):
    """Raised when a parse is attempted but the optional UnityPy dependency is absent."""


@dataclass
class ExtractedString:
    """One string pulled from a Unity object, with its provenance."""
    text: str
    container: str          # extracted/-relative path of the source .assets/.bundle
    asset_name: str         # the object's m_Name (best-effort)
    path_id: int            # SerializedFile object path-id (stable Unity object key)
    class_name: str         # "TextAsset" | "MonoBehaviour"
    raw: bytes | None = None  # original TextAsset body (for dumping); None for field strings


def available() -> bool:
    """True when UnityPy can be imported (the `unity` extra is installed)."""
    import importlib.util

    return importlib.util.find_spec("UnityPy") is not None


def unitypy_version() -> str | None:
    """Installed UnityPy version for provenance, or None when absent."""
    import importlib.metadata

    try:
        return importlib.metadata.version("UnityPy")
    except importlib.metadata.PackageNotFoundError:
        return None


def _coerce_script(value: object, max_bytes: int) -> tuple[str, bytes]:
    """Normalize a TextAsset m_Script (str or bytes) to (text, raw bytes), truncated."""
    if isinstance(value, bytes):
        raw = value[:max_bytes]
        return raw.decode("utf-8", "replace"), raw
    text = str(value)[:max_bytes]
    return text, text.encode("utf-8", "replace")


def _walk_strings(node: object, max_count: int, max_len: int) -> list[str]:
    """Collect string leaves from a parsed typetree (nested dict/list), bounded.

    MonoBehaviour typetrees are arbitrarily nested; we only want the string-valued leaves
    (where URLs, keys, and config live). Non-string scalars are ignored. Stops at max_count.
    """
    out: list[str] = []

    def visit(n: object) -> None:
        if len(out) >= max_count:
            return
        if isinstance(n, str):
            if n:
                out.append(n[:max_len])
        elif isinstance(n, dict):
            for v in n.values():
                if len(out) >= max_count:
                    return
                visit(v)
        elif isinstance(n, (list, tuple)):
            for v in n:
                if len(out) >= max_count:
                    return
                visit(v)

    visit(node)
    return out


def _class_of(obj: object) -> str | None:
    """The Unity class name we care about for `obj` (an ObjectReader), or None to skip."""
    type_obj = getattr(obj, "type", None)
    name = getattr(type_obj, "name", None)
    if name in (_TEXTASSET, _MONOBEHAVIOUR):
        return name
    return None


def _name_of(data: object, fallback_obj: object) -> str:
    """Best-effort m_Name for an extracted object."""
    name = getattr(data, "m_Name", None)
    if isinstance(name, str) and name:
        return name
    peek = getattr(fallback_obj, "peek_name", None)
    if callable(peek):
        try:
            peeked = peek()
            if isinstance(peeked, str) and peeked:
                return peeked
        except Exception:  # noqa: BLE001 — UnityPy can throw on stripped/exotic objects
            pass
    return ""


def _extract_object(obj: object, container: str, *, max_bytes_per_obj: int,
                    max_strings_per_obj: int) -> list[ExtractedString]:
    """Pull ExtractedStrings from one UnityPy object reader. Fail-soft per object."""
    cls = _class_of(obj)
    if cls is None:
        return []
    path_id = int(getattr(obj, "path_id", 0) or 0)
    if cls == _TEXTASSET:
        data = obj.read()
        script = getattr(data, "m_Script", None)
        if script is None:
            return []
        text, raw = _coerce_script(script, max_bytes_per_obj)
        if not text:
            return []
        return [ExtractedString(text=text, container=container, asset_name=_name_of(data, obj),
                                path_id=path_id, class_name=cls, raw=raw)]
    # MonoBehaviour: walk the typetree for string leaves.
    tree = obj.read_typetree()
    name = tree.get("m_Name", "") if isinstance(tree, dict) else ""
    strings = _walk_strings(tree, max_strings_per_obj, max_bytes_per_obj)
    return [ExtractedString(text=s, container=container, asset_name=name if isinstance(name, str) else "",
                            path_id=path_id, class_name=cls) for s in strings]


def parse_container(path: Path, container_rel: str, *, max_obj: int = const_max_obj,
                    max_bytes_per_obj: int = const_max_bytes_per_obj,
                    max_strings_per_obj: int = const_max_strings_per_obj) -> list[ExtractedString]:
    """Extract strings from one Unity serialized container. Bounded and fail-soft.

    Raises UnityPyUnavailable if the dependency is missing (callers gate on available()).
    A non-Unity / corrupt file, or any per-object read error, yields no findings rather than
    raising, so one bad asset never aborts an analysis.
    """
    try:
        import UnityPy
    except ImportError as exc:  # pragma: no cover - exercised via available() gate
        raise UnityPyUnavailable("UnityPy is not installed") from exc

    try:
        env = UnityPy.load(str(path))
    except Exception:  # noqa: BLE001 — UnityPy raises a wide variety on bad input
        logger.debug("unityasset: cannot load %s", path, exc_info=True)
        return []

    out: list[ExtractedString] = []
    for index, obj in enumerate(env.objects):
        if index >= max_obj:
            break
        try:
            out.extend(_extract_object(obj, container_rel, max_bytes_per_obj=max_bytes_per_obj,
                                       max_strings_per_obj=max_strings_per_obj))
        except Exception:  # noqa: BLE001 — exotic Unity versions / stripped objects
            logger.debug("unityasset: skipping unreadable object in %s", path, exc_info=True)
    return out
