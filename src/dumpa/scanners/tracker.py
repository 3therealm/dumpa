"""Tracker scanner: privacy/SDK inventory via the trackers rule bundle.

Applies the built-in `trackers` bundle (content matchers over dex/native/manifest)
to the workspace's extracted tree. Each finding carries the tracker taxonomy
(`category`) and SDK owner (`owner`) as attributes, plus evidence (matched class
path / domain, file, and byte offset).
"""

from __future__ import annotations

from dumpa.core.report import Finding
from dumpa.core.rules import apply_bundle, load_builtin
from dumpa.core.workspace import Workspace

const_tracker_bundle = "trackers"


def scan(ws: Workspace) -> list[Finding]:
    """Detect tracker SDKs by applying the built-in trackers bundle to extracted/."""
    if not ws.extracted_dir.is_dir():
        return []
    return apply_bundle(load_builtin(const_tracker_bundle), ws.extracted_dir)
