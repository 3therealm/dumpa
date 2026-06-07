"""Structured `AndroidManifest.xml` view, built on the zero-dep AXML decoder.

`core.axml` turns the compiled binary manifest into a generic element tree; this module
maps that tree into the manifest-specific `ManifestInfo` — the shared primitive the
report header (`reporting`), the manifest privacy audit (`scanners.manifest_privacy`),
and the manifest rule matcher (`core.rules`) all read. `load_manifest(ws)` parses a
workspace's manifest once and caches it (the file is tiny but three consumers ask).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dumpa.core.axml import AttrValue, AxmlElement, parse_axml
from dumpa.core.errors import AxmlError
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_manifest_name = "AndroidManifest.xml"

# Element tags that declare an app component.
_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


@dataclass(frozen=True)
class IntentData:
    """A `<data>` entry inside an intent filter (deep-link addressing)."""
    scheme: str | None = None
    host: str | None = None
    path: str | None = None


@dataclass(frozen=True)
class IntentFilter:
    """One `<intent-filter>`: its actions, categories, and data entries."""
    actions: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    data: tuple[IntentData, ...] = ()
    auto_verify: bool = False


@dataclass(frozen=True)
class Component:
    """A declared component (activity/service/receiver/provider)."""
    type: str
    name: str
    exported: bool | None = None          # None = attribute absent
    permission: str | None = None
    intent_filters: tuple[IntentFilter, ...] = ()

    @property
    def exported_effective(self) -> bool:
        """The effective exported state: explicit value, else Android's intent-filter default."""
        if self.exported is not None:
            return self.exported
        return bool(self.intent_filters)


@dataclass(frozen=True)
class ManifestInfo:
    """The structured manifest facts every consumer reads."""
    package: str | None = None
    version_code: str | None = None
    version_name: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    permissions: tuple[str, ...] = ()
    debuggable: bool = False
    allow_backup: bool | None = None       # None = absent (defaults true pre-Android-12)
    components: tuple[Component, ...] = ()

    @property
    def exported_components(self) -> tuple[Component, ...]:
        return tuple(c for c in self.components if c.exported_effective)


def _as_str(value: AttrValue | None) -> str | None:
    """Coerce an attribute value to a non-empty string, or None."""
    if value is None or isinstance(value, bool):
        return None
    return value or None


def _as_bool(value: AttrValue | None) -> bool | None:
    """Coerce an attribute value to a bool, or None when absent/uninterpretable."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value == "true":
            return True
        if value == "false":
            return False
    return None


def _intent_data(elem: AxmlElement) -> IntentData:
    return IntentData(
        scheme=_as_str(elem.attrs.get("scheme")),
        host=_as_str(elem.attrs.get("host")),
        path=_as_str(elem.attrs.get("path")),
    )


def _intent_filter(elem: AxmlElement) -> IntentFilter:
    actions: list[str] = []
    categories: list[str] = []
    data: list[IntentData] = []
    for child in elem.children:
        name = _as_str(child.attrs.get("name"))
        if child.tag == "action" and name:
            actions.append(name)
        elif child.tag == "category" and name:
            categories.append(name)
        elif child.tag == "data":
            data.append(_intent_data(child))
    return IntentFilter(
        actions=tuple(actions), categories=tuple(categories), data=tuple(data),
        auto_verify=_as_bool(elem.attrs.get("autoVerify")) or False,
    )


def _component(elem: AxmlElement) -> Component:
    filters = tuple(_intent_filter(c) for c in elem.children if c.tag == "intent-filter")
    return Component(
        type=elem.tag,
        name=_as_str(elem.attrs.get("name")) or "",
        exported=_as_bool(elem.attrs.get("exported")),
        permission=_as_str(elem.attrs.get("permission")),
        intent_filters=filters,
    )


def _from_document_root(root: AxmlElement) -> ManifestInfo:
    permissions: list[str] = []
    components: list[Component] = []
    min_sdk: str | None = None
    target_sdk: str | None = None
    debuggable = False
    allow_backup: bool | None = None

    for child in root.children:
        if child.tag == "uses-permission":
            name = _as_str(child.attrs.get("name"))
            if name:
                permissions.append(name)
        elif child.tag == "uses-sdk":
            min_sdk = _as_str(child.attrs.get("minSdkVersion")) or min_sdk
            target_sdk = _as_str(child.attrs.get("targetSdkVersion")) or target_sdk
        elif child.tag == "application":
            debuggable = _as_bool(child.attrs.get("debuggable")) or False
            allow_backup = _as_bool(child.attrs.get("allowBackup"))
            for node in child.children:
                if node.tag in _COMPONENT_TAGS:
                    components.append(_component(node))

    return ManifestInfo(
        package=_as_str(root.attrs.get("package")),
        version_code=_as_str(root.attrs.get("versionCode")),
        version_name=_as_str(root.attrs.get("versionName")),
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        permissions=tuple(permissions),
        debuggable=debuggable,
        allow_backup=allow_backup,
        components=tuple(components),
    )


def parse_manifest_bytes(data: bytes) -> ManifestInfo:
    """Decode binary AXML bytes into a ManifestInfo. Raise AxmlError on malformed input."""
    doc = parse_axml(data)
    if doc.root is None:
        raise AxmlError("manifest has no root element")
    return _from_document_root(doc.root)


@lru_cache(maxsize=8)
def _cached_parse(path: str, size: int, mtime_ns: int) -> ManifestInfo | None:
    try:
        data = Path(path).read_bytes()
        return parse_manifest_bytes(data)
    except (OSError, AxmlError):
        logger.debug("manifest parse failed for %s", path, exc_info=True)
        return None


def load_manifest(ws: Workspace) -> ManifestInfo | None:
    """Parse the workspace's AndroidManifest.xml; None if absent or unparseable.

    Cached on (path, size, mtime) so engine/tracker/privacy scanners plus the report
    builder share a single parse of the same workspace's manifest.
    """
    path = ws.extracted_dir / const_manifest_name
    try:
        stat = path.stat()
    except OSError:
        return None
    return _cached_parse(str(path), stat.st_size, stat.st_mtime_ns)
