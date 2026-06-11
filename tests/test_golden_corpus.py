"""Golden-sample regression over real corpus apps.

This is the real-app counterpart to the synthetic unit tests: it runs the full
analysis pipeline over actual game APKs/XAPKs and compares a stable projection
(see `tests/_golden.py`) against committed snapshots under `tests/golden/`. It
catches "tracker disappeared" / "engine misdetected" / "permission set changed"
regressions that synthetic inputs cannot.

The corpus is large and gitignored, so it is never committed; only the small
snapshot JSONs are. The whole module therefore **skips** when the corpus dir is
absent (e.g. CI), and is a local/nightly guard.

Run / regenerate snapshots:

    DUMPA_UPDATE_GOLDEN=1 DUMPA_CORPUS_DIR=corpus pytest tests/test_golden_corpus.py

then review the diff under tests/golden/ and commit. Without the update flag the
test asserts equality.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from _golden import project

from dumpa.commands.analyze import report_for_input
from dumpa.core.errors import ToolNotFoundError
from dumpa.core.tools import build_default_registry

# Representative, engine-diverse, mostly-small corpus apps. Each present file with
# a committed golden is checked; missing files / missing goldens skip individually.
CANDIDATES = (
    "com.watabou.pixeldungeon.apk",
    "com.smilerlee.klondike.apk",
    "com.mobilegame.wordsearch.apk",
    "io.anuke.mindustry.apk",
    "org.godotengine.ceiStudiosRamMandirGame.apk",
    "com.unciv.app.xapk",
    "com.shatteredpixel.shatteredpixeldungeon.xapk",
)

_GOLDEN_DIR = Path(__file__).parent / "golden"


def _corpus_dir() -> Path:
    return Path(os.environ.get("DUMPA_CORPUS_DIR", Path(__file__).parent.parent / "corpus"))


def _apktool_available() -> bool:
    try:
        build_default_registry().resolve("apktool")
    except ToolNotFoundError:
        return False
    return True


_CORPUS = _corpus_dir()
pytestmark = pytest.mark.skipif(
    not (_CORPUS.is_dir() and any(_CORPUS.iterdir())),
    reason=f"corpus dir absent or empty ({_CORPUS}); set DUMPA_CORPUS_DIR to enable",
)


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force network lookups off so the projection is deterministic and offline."""
    monkeypatch.setenv("DUMPA_PLAY_LOOKUP", "0")


@pytest.mark.parametrize("name", CANDIDATES)
def test_corpus_app_matches_golden(name: str) -> None:
    app = _CORPUS / name
    if not app.is_file():
        pytest.skip(f"{name} not present in corpus")
    if app.suffix == ".xapk" and not _apktool_available():
        pytest.skip(f"{name} is an xapk and apktool is unavailable")

    snapshot = project(report_for_input(app))
    golden_path = _GOLDEN_DIR / f"{name}.json"

    if os.environ.get("DUMPA_UPDATE_GOLDEN") == "1":
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
                               encoding="UTF-8")
        return

    if not golden_path.is_file():
        pytest.skip(f"no golden for {name}; run with DUMPA_UPDATE_GOLDEN=1 to create one")

    expected = json.loads(golden_path.read_text(encoding="UTF-8"))
    assert snapshot == expected
