"""Game-type scanner: resolve the app's Google Play genre into findings.

Thin wrapper over `core.gametype.resolve_game_types` (networked, opt-in, cached). Emits
one `game-type` finding per resolved genre; the genre and the dump.cs categories it
selects are carried as attributes, with the Play URL + fetch date as evidence so a
networked lookup stays auditable. No-ops when the package is unknown, the lookup is
disabled, or the app is not listed.
"""

from __future__ import annotations

from dumpa.core.config import load_config
from dumpa.core.gametype import resolve_game_types
from dumpa.core.report import Confidence, Evidence, Finding, FindingState, Location
from dumpa.core.workspace import Workspace

const_kind = "game-type"


def scan(ws: Workspace) -> list[Finding]:
    cfg = load_config().analysis
    types = resolve_game_types(ws, allow_network=cfg.play_lookup,
                               timeout=cfg.play_timeout, ttl_days=cfg.play_cache_ttl_days)
    findings: list[Finding] = []
    for t in types:
        findings.append(Finding(
            kind=const_kind, subject=t.genre, confidence=Confidence.MEDIUM,
            state=FindingState.PRESENT,
            attributes={"genre_id": t.genre_id, "categories": ",".join(t.categories)},
            evidence=[Evidence(
                description=f"Google Play genre {t.genre} ({t.genre_id}); fetched {t.fetched}",
                snippet=t.source_url, tool="playstore")],
            locations=[Location(domain="play.google.com")],
        ))
    return findings
