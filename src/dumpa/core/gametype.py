"""Game-type resolution: package -> Play genre -> dump.cs pattern categories.

Shared by the gametype scanner (which emits `game-type` findings) and the dumpcs
scanner (which selects genre-specific pattern bundles). To keep the Play lookup to one
fetch per workspace, the resolved result is memoized in `dumps/gametype.json`; both
scanners read that sidecar after the first resolution. The genre->category mapping is
data (`dumpa/data/gametype_map.toml`); an unmapped genre yields no genre-specific
category (the dumpcs scanner still runs the always-on bundles).
"""

from __future__ import annotations

import importlib.resources
import json
import logging
import tomllib
from dataclasses import asdict, dataclass
from typing import Any, cast

from dumpa.core.manifest import load_manifest
from dumpa.core.playstore import PlayListing, fetch_listing
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_data_package = "dumpa.data"
const_map_resource = "gametype_map.toml"


@dataclass(frozen=True)
class GameType:
    """A resolved Play genre plus the dump.cs categories it selects."""
    genre: str
    genre_id: str
    categories: tuple[str, ...]
    source_url: str
    fetched: str

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "categories": list(self.categories)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GameType:
        return cls(
            genre=str(data["genre"]), genre_id=str(data["genre_id"]),
            categories=tuple(str(c) for c in data.get("categories", [])),
            source_url=str(data.get("source_url", "")),
            fetched=str(data.get("fetched", "")),
        )


def _load_genre_map() -> dict[str, tuple[str, ...]]:
    """Load the genreId -> categories table from dumpa/data/gametype_map.toml."""
    resource = importlib.resources.files(const_data_package) / const_map_resource
    with resource.open("rb") as f:
        data = tomllib.load(f)
    raw = data.get("map", {})
    if not isinstance(raw, dict):
        return {}
    out: dict[str, tuple[str, ...]] = {}
    for genre_id, cats in cast("dict[str, Any]", raw).items():
        if isinstance(cats, list):
            out[str(genre_id)] = tuple(str(c) for c in cats)
    return out


def _categories_for(genre_id: str) -> tuple[str, ...]:
    return _load_genre_map().get(genre_id, ())


def _to_game_type(listing: PlayListing) -> GameType:
    return GameType(
        genre=listing.genre, genre_id=listing.genre_id,
        categories=_categories_for(listing.genre_id),
        source_url=listing.url, fetched=listing.fetched,
    )


def _read_sidecar(ws: Workspace) -> list[GameType] | None:
    path = ws.gametype_sidecar
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="UTF-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, list):
        return None
    try:
        return [GameType.from_dict(d) for d in data]
    except (KeyError, TypeError, ValueError):
        return None


def _write_sidecar(ws: Workspace, types: list[GameType]) -> None:
    path = ws.gametype_sidecar
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([t.to_dict() for t in types], indent=2, sort_keys=True) + "\n",
                        encoding="UTF-8")
    except OSError:
        logger.debug("gametype: cannot write sidecar %s", path, exc_info=True)


def resolve_game_types(ws: Workspace, *, allow_network: bool, timeout: int,
                       ttl_days: int) -> list[GameType]:
    """Resolve the workspace's game types, memoized in dumps/gametype.json.

    Sidecar hit returns immediately. Otherwise read the package from the manifest, look
    up the Play genre (cache-or-network per `allow_network`), map it to categories, and
    write the sidecar (even when empty, so the lookup happens once per workspace).
    """
    cached = _read_sidecar(ws)
    if cached is not None:
        return cached

    manifest = load_manifest(ws)
    package = manifest.package if manifest else None
    types: list[GameType] = []
    if package:
        listing = fetch_listing(package, cache_dir=ws.playstore_cache_dir,
                                allow_network=allow_network, timeout=timeout,
                                ttl_days=ttl_days)
        if listing is not None:
            types = [_to_game_type(listing)]
    _write_sidecar(ws, types)
    return types
