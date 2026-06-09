"""Cross-reference index: where each entity appears across every analysis layer.

The unified finding model already records *where* a finding lives (`Location`: file path,
dex class, manifest entry, domain, RVA/offset). This module joins those — plus the
structural sidecars (native symbols, dex classes, manifest components, dump.cs methods) —
into one index keyed by entity, so a single domain/class/string/symbol can be traced
across manifest, smali, Java, native, dump.cs, resources, and assets at once.

It is a derived artifact, not a scanner: `build_xref` consumes findings + sidecars and
emits an `Xref`. The persisted artifact (`dumps/xref.json`) holds only entities that span
**two or more layers** — the correlations worth seeing; the single-layer bulk (every lone
native symbol) is never stored. `query_xref` answers about one specific entity, including
single-layer ones, with a streaming pass that materializes nothing.

Resources are enumerated from the `dumps/resources/` sidecars (the `resources` scanner's
parse of `resources.arsc`): every resource name and string value joins the RESOURCE layer.
Assets still contribute only via existing findings' file paths (finding-derived). C++
symbol demangling remains deferred and recorded in provenance.
"""

from __future__ import annotations

import enum
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from dumpa.core.dex import _descriptor_to_dotted
from dumpa.core.dumpcs_methods import iter_method_sigs
from dumpa.core.jni import decode_jni
from dumpa.core.manifest import load_manifest
from dumpa.core.report import Finding, Location
from dumpa.core.workspace import Workspace

const_xref_schema_version = 1
const_deferred = ("cpp-demangle",)

_GENERIC_ARITY = re.compile(r"`\d+")


class EntityType(enum.StrEnum):
    """The kind of thing an entity is — namespaces the key so types never collide."""
    DOMAIN = "domain"
    CLASS = "class"
    STRING = "string"
    SYMBOL = "symbol"


class Layer(enum.StrEnum):
    """An analysis layer an entity can appear in."""
    MANIFEST = "manifest"
    SMALI = "smali"        # smali/*.smali and classesN.dex (one logical layer)
    JAVA = "java"          # decompiled/ (index-if-present)
    NATIVE = "native"      # lib/<abi>/*.so
    DUMPCS = "dumpcs"      # dumps/dump.cs
    RESOURCE = "resource"  # res/, resources.arsc (enumerated from dumps/resources/)
    ASSET = "asset"        # assets/, dumps/{cocos,godot}/ (finding-derived)


@dataclass(frozen=True)
class Appearance:
    """One place an entity shows up: which layer, and the precise location."""
    layer: Layer
    location: Location

    def to_dict(self) -> dict[str, Any]:
        return {"layer": self.layer.value, "location": self.location.to_dict()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Appearance:
        return cls(layer=Layer(str(data["layer"])),
                   location=Location.from_dict(dict(data.get("location", {}))))


@dataclass(frozen=True)
class XrefEntity:
    """One entity and every layer it was found in."""
    type: EntityType
    key: str                              # normalized join key
    display: str                          # original spelling for humans
    appearances: tuple[Appearance, ...]
    aliases: tuple[str, ...] = ()         # e.g. a SYMBOL's JNI-decoded class key

    @property
    def layers(self) -> frozenset[Layer]:
        return frozenset(a.layer for a in self.appearances)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "type": self.type.value,
            "key": self.key,
            "display": self.display,
            "appearances": [a.to_dict() for a in self.appearances],
        }
        if self.aliases:
            out["aliases"] = list(self.aliases)
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> XrefEntity:
        return cls(
            type=EntityType(str(data["type"])),
            key=str(data["key"]),
            display=str(data.get("display", data["key"])),
            appearances=tuple(Appearance.from_dict(a) for a in data.get("appearances", [])),
            aliases=tuple(str(a) for a in data.get("aliases", [])),
        )


@dataclass(frozen=True)
class XrefProvenance:
    """Reproducibility + honesty: what input, when, which layers were present, what's deferred."""
    input_sha256: str
    built: str                            # ISO-8601 UTC, stamped by the caller
    layers_present: tuple[Layer, ...]
    deferred: tuple[str, ...] = const_deferred

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_sha256": self.input_sha256,
            "built": self.built,
            "layers_present": [lyr.value for lyr in self.layers_present],
            "deferred": list(self.deferred),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> XrefProvenance:
        return cls(
            input_sha256=str(data["input_sha256"]),
            built=str(data["built"]),
            layers_present=tuple(Layer(str(lyr)) for lyr in data.get("layers_present", [])),
            deferred=tuple(str(d) for d in data.get("deferred", const_deferred)),
        )


@dataclass(frozen=True)
class Xref:
    """The cross-reference index: provenance + the multi-layer entities (correlations)."""
    provenance: XrefProvenance
    entities: tuple[XrefEntity, ...]
    schema_version: int = const_xref_schema_version

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "provenance": self.provenance.to_dict(),
            "entities": [e.to_dict() for e in self.entities],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Xref:
        return cls(
            schema_version=int(data.get("schema_version", const_xref_schema_version)),
            provenance=XrefProvenance.from_dict(dict(data["provenance"])),
            entities=tuple(XrefEntity.from_dict(e) for e in data.get("entities", [])),
        )


# --- normalization + layer mapping (pure) ---------------------------------------------

def normalize(entity_type: EntityType, raw: str) -> str:
    """Canonical join key for an entity. Per-type rules (see the design doc §3)."""
    if entity_type is EntityType.DOMAIN:
        return raw.strip().lower()
    if entity_type is EntityType.CLASS:
        dotted = _descriptor_to_dotted(raw) if raw.startswith("L") and raw.endswith(";") else raw
        dotted = dotted.replace("/", ".")
        return _GENERIC_ARITY.sub("", dotted)      # drop generic arity (`List`1` -> `List`)
    return raw                                      # STRING / SYMBOL: exact, case-sensitive


def layer_of(file_path: str | None) -> Layer | None:
    """Map a Location.file_path to its analysis layer, or None when it places nowhere."""
    if not file_path:
        return None
    p = file_path.replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    if base == "AndroidManifest.xml":
        return Layer.MANIFEST
    if p.endswith(".smali") or "/smali" in p or p.startswith("smali") or base.endswith(".dex"):
        return Layer.SMALI
    if p.startswith("decompiled/") or "/decompiled/" in p:
        return Layer.JAVA
    if base == "dump.cs":
        return Layer.DUMPCS
    if p.startswith("lib/") and base.endswith(".so"):
        return Layer.NATIVE
    if p.startswith("res/") or base == "resources.arsc":
        return Layer.RESOURCE
    if p.startswith("assets/") or p.startswith("dumps/cocos/") or p.startswith("dumps/godot/"):
        return Layer.ASSET
    return None


# --- entity sources -------------------------------------------------------------------

_Yield = tuple[EntityType, str, Layer, Location]


def _from_findings(findings: list[Finding]) -> Iterator[_Yield]:
    """Entities carried by finding locations + matched-string evidence."""
    for f in findings:
        loc_paths = {loc.file_path for loc in f.locations if loc.file_path}
        for loc in f.locations:
            layer = layer_of(loc.file_path)
            if loc.domain and layer is not None:
                yield (EntityType.DOMAIN, loc.domain, layer, loc)
            if loc.dex_class:
                yield (EntityType.CLASS, loc.dex_class, Layer.SMALI, loc)
            if loc.manifest_entry:
                yield (EntityType.CLASS, loc.manifest_entry, Layer.MANIFEST, loc)
        # matched literal -> STRING, only when it is a real value (not a path echo)
        first_layer = next((layer_of(loc.file_path) for loc in f.locations
                            if layer_of(loc.file_path) is not None), None)
        if first_layer is not None:
            anchor = next((loc for loc in f.locations if layer_of(loc.file_path) == first_layer), None)
            for ev in f.evidence:
                if ev.snippet and ev.snippet not in loc_paths and anchor is not None:
                    yield (EntityType.STRING, ev.snippet, first_layer, anchor)


def _from_native(ws: Workspace) -> Iterator[_Yield]:
    """SYMBOL entities (exports + imports) from dumps/native/*.json, plus JNI class aliases."""
    if not ws.native_dir.is_dir():
        return
    for sidecar in sorted(ws.native_dir.glob("*.json")):
        try:
            data = json.loads(sidecar.read_text(encoding="UTF-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        abi = str(data.get("abi", ""))
        lib = str(data.get("lib", ""))
        rel = f"lib/{abi}/{lib}" if abi and lib else lib
        for exp in data.get("exports", []):
            name = str(exp.get("name", ""))
            if not name:
                continue
            loc = Location(file_path=rel, rva=exp.get("rva"))
            yield (EntityType.SYMBOL, name, Layer.NATIVE, loc)
            decoded = decode_jni(name)
            if decoded is not None:
                yield (EntityType.CLASS, decoded[0], Layer.NATIVE, loc)
        for imp in data.get("imports", []):
            name = str(imp.get("name", ""))
            if name:
                yield (EntityType.SYMBOL, name, Layer.NATIVE, Location(file_path=rel))


def _from_dex(ws: Workspace) -> Iterator[_Yield]:
    """CLASS entities from the dex class inventory sidecars (dumps/dex/*.json)."""
    if not ws.dex_dir.is_dir():
        return
    for sidecar in sorted(ws.dex_dir.glob("*.json")):
        try:
            data = json.loads(sidecar.read_text(encoding="UTF-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        dex_name = str(data.get("dex", sidecar.stem))
        for cls in data.get("classes", []):
            name = str(cls.get("name", ""))
            if name:
                yield (EntityType.CLASS, name, Layer.SMALI,
                       Location(file_path=dex_name, dex_class=name))


def _from_manifest(ws: Workspace) -> Iterator[_Yield]:
    """CLASS entities from declared manifest components."""
    info = load_manifest(ws)
    if info is None:
        return
    for comp in info.components:
        if comp.name:
            yield (EntityType.CLASS, comp.name, Layer.MANIFEST,
                   Location(manifest_entry=comp.name))


def _dumpcs_path(ws: Workspace) -> Path:
    return ws.dumps_dir / "dump.cs"


def _from_dumpcs(ws: Workspace) -> Iterator[_Yield]:
    """CLASS entities: the declaring type of each dump.cs method (streamed)."""
    path = _dumpcs_path(ws)
    if not path.is_file():
        return
    loc = Location(file_path="dump.cs")
    seen: set[str] = set()
    for sig in iter_method_sigs(path):
        declaring = sig.split("::", 1)[0]
        if declaring and declaring not in seen:
            seen.add(declaring)
            yield (EntityType.CLASS, declaring, Layer.DUMPCS, loc)


def _from_resources(ws: Workspace) -> Iterator[_Yield]:
    """STRING entities (resource names + string values) from dumps/resources/*.json."""
    if not ws.resources_dir.is_dir():
        return
    loc = Location(file_path="resources.arsc")
    for sidecar in sorted(ws.resources_dir.glob("*.json")):
        try:
            data = json.loads(sidecar.read_text(encoding="UTF-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        for entry in data.get("strings", []):
            name = str(entry.get("name", ""))
            value = str(entry.get("value", ""))
            if name:
                yield (EntityType.STRING, name, Layer.RESOURCE, loc)
            if value:
                yield (EntityType.STRING, value, Layer.RESOURCE, loc)


def _iter_sources(ws: Workspace, findings: list[Finding]) -> Iterator[_Yield]:
    yield from _from_findings(findings)
    yield from _from_native(ws)
    yield from _from_dex(ws)
    yield from _from_manifest(ws)
    yield from _from_dumpcs(ws)
    yield from _from_resources(ws)


def _layers_present(ws: Workspace, findings: list[Finding]) -> tuple[Layer, ...]:
    present: set[Layer] = set()
    if load_manifest(ws) is not None:
        present.add(Layer.MANIFEST)
    if ws.dex_dir.is_dir() and any(ws.dex_dir.glob("*.json")):
        present.add(Layer.SMALI)
    if ws.native_dir.is_dir() and any(ws.native_dir.glob("*.json")):
        present.add(Layer.NATIVE)
    if _dumpcs_path(ws).is_file():
        present.add(Layer.DUMPCS)
    if ws.resources_dir.is_dir() and any(ws.resources_dir.glob("*.json")):
        present.add(Layer.RESOURCE)
    if ws.decompiled_dir.is_dir():
        present.add(Layer.JAVA)
    for f in findings:
        for loc in f.locations:
            layer = layer_of(loc.file_path)
            if layer is not None:
                present.add(layer)
    return tuple(sorted(present, key=lambda lyr: lyr.value))


# --- build + query --------------------------------------------------------------------

def build_xref(ws: Workspace, findings: list[Finding], *, input_sha256: str,
               built: str) -> Xref:
    """Build the correlation index: entities appearing in two or more layers.

    Two streaming passes: tally each entity's layer-set, then materialize appearances only
    for keys that span >= 2 layers. Single-layer entities are dropped from the artifact.
    """
    tally: dict[tuple[EntityType, str], set[Layer]] = {}
    for etype, raw, layer, _loc in _iter_sources(ws, findings):
        tally.setdefault((etype, normalize(etype, raw)), set()).add(layer)

    multi = {key for key, layers in tally.items() if len(layers) >= 2}

    appearances: dict[tuple[EntityType, str], list[Appearance]] = {}
    display: dict[tuple[EntityType, str], str] = {}
    aliases: dict[tuple[EntityType, str], set[str]] = {}
    for etype, raw, layer, loc in _iter_sources(ws, findings):
        key = (etype, normalize(etype, raw))
        if key not in multi:
            continue
        appearances.setdefault(key, []).append(Appearance(layer=layer, location=loc))
        display.setdefault(key, raw)
        if etype is EntityType.SYMBOL:
            decoded = decode_jni(raw)
            if decoded is not None:
                aliases.setdefault(key, set()).add(decoded[0])

    entities = tuple(
        XrefEntity(
            type=etype, key=norm, display=display[(etype, norm)],
            appearances=tuple(appearances[(etype, norm)]),
            aliases=tuple(sorted(aliases.get((etype, norm), ()))),
        )
        for (etype, norm) in sorted(appearances, key=lambda k: (k[0].value, k[1]))
    )
    provenance = XrefProvenance(
        input_sha256=input_sha256, built=built,
        layers_present=_layers_present(ws, findings),
    )
    return Xref(provenance=provenance, entities=entities)


def query_xref(ws: Workspace, findings: list[Finding], entity: str, *,
               case_insensitive: bool = False) -> XrefEntity | None:
    """Find every appearance of one entity, including single-layer ones (streaming)."""
    target = entity.lower() if case_insensitive else entity
    matches: dict[EntityType, list[Appearance]] = {}
    display: dict[EntityType, str] = {}
    aliases: dict[EntityType, set[str]] = {}
    for etype, raw, layer, loc in _iter_sources(ws, findings):
        norm = normalize(etype, raw)
        cmp = norm.lower() if case_insensitive else norm
        if cmp != target:
            continue
        matches.setdefault(etype, []).append(Appearance(layer=layer, location=loc))
        display.setdefault(etype, raw)
        if etype is EntityType.SYMBOL:
            decoded = decode_jni(raw)
            if decoded is not None:
                aliases.setdefault(etype, set()).add(decoded[0])
    if not matches:
        return None
    # If several types match the same string, prefer the one with the most appearances.
    etype = max(matches, key=lambda t: len(matches[t]))
    return XrefEntity(
        type=etype, key=normalize(etype, display[etype]), display=display[etype],
        appearances=tuple(matches[etype]), aliases=tuple(sorted(aliases.get(etype, ()))),
    )


# --- serialization --------------------------------------------------------------------

def to_json(xref: Xref) -> str:
    return json.dumps(xref.to_dict(), indent=2, sort_keys=True) + "\n"


def write_xref(xref: Xref, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(xref), encoding="UTF-8")


def read_xref(path: Path) -> Xref | None:
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="UTF-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(loaded, dict):
        return None
    try:
        return Xref.from_dict(cast("dict[str, Any]", loaded))
    except (KeyError, TypeError, ValueError):
        return None


# --- rendering ------------------------------------------------------------------------

def render_xref_list(xref: Xref, *, min_layers: int = 2) -> str:
    """Text view: every entity spanning >= min_layers, one per line."""
    rows = [e for e in xref.entities if len(e.layers) >= min_layers]
    lines = [f"cross-layer correlations: {len(rows)} "
             f"(>= {min_layers} layers; from {len(xref.entities)} indexed)"]
    for e in rows:
        layers = ",".join(sorted(lyr.value for lyr in e.layers))
        lines.append(f"  [{e.type.value}] {e.display}  ({layers})")
    if not rows:
        lines.append("  (none)")
    return "\n".join(lines) + "\n"


def render_xref_entity(entity: XrefEntity) -> str:
    """Text view: one entity and every place it appears, grouped by layer."""
    lines = [f"[{entity.type.value}] {entity.display}"]
    if entity.aliases:
        lines.append(f"  aliases: {', '.join(entity.aliases)}")
    by_layer: dict[Layer, list[Location]] = {}
    for a in entity.appearances:
        by_layer.setdefault(a.layer, []).append(a.location)
    for layer in sorted(by_layer, key=lambda lyr: lyr.value):
        lines.append(f"  {layer.value}:")
        for loc in by_layer[layer]:
            detail = loc.to_dict()
            lines.append(f"    {detail}")
    return "\n".join(lines) + "\n"
