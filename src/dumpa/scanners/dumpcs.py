"""dump.cs scanner: genre-selected regex patterns over the IL2CPP dump.

No-ops unless `dumps/dump.cs` exists (produced by `dump-il2cpp` / analyze auto-dump).
Resolves the game type (shared sidecar with the gametype scanner), unions the selected
genre categories, and runs the dumpcs rule bundles over `dump.cs` via the streaming
content matcher. Always-on bundles (general / anti-cheat / obfuscation) carry no
`game_types` and run regardless of genre; genre bundles run only when their category is
selected.

Streaming: `scan_content_rules` reuses `_scan_content`'s 1 MiB chunked reads, so a
hundreds-of-MB dump.cs is scanned with bounded memory.
"""

from __future__ import annotations

from dumpa.core.config import load_config
from dumpa.core.gametype import resolve_game_types
from dumpa.core.report import Finding
from dumpa.core.rules import Rule, load_builtin, scan_content_rules
from dumpa.core.workspace import Workspace

const_dump_cs = "dump.cs"
const_dumpcs_bundles = (
    "dumpcs_general", "dumpcs_match3", "dumpcs_rpg", "dumpcs_strategy",
    "dumpcs_anticheat", "dumpcs_obfuscation",
)


def _selected(rule: Rule, categories: set[str]) -> bool:
    """Always-on rules (no game_types) always run; genre rules need a selected category."""
    return not rule.game_types or bool(set(rule.game_types) & categories)


def scan(ws: Workspace) -> list[Finding]:
    if not (ws.dumps_dir / const_dump_cs).is_file():
        return []
    cfg = load_config().analysis
    types = resolve_game_types(ws, allow_network=cfg.play_lookup,
                               timeout=cfg.play_timeout, ttl_days=cfg.play_cache_ttl_days)
    categories: set[str] = set()
    for t in types:
        categories.update(t.categories)

    findings: list[Finding] = []
    for name in const_dumpcs_bundles:
        bundle = load_builtin(name)
        rules = [r for r in bundle.rules if _selected(r, categories)]
        findings.extend(scan_content_rules(rules, bundle, ws.dumps_dir))
    return findings
