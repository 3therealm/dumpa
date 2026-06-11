"""The workspace: one reproducible directory per analyzed app.

An APK/XAPK is extracted once into a workspace; `analyze`, `dump-il2cpp`, and later
scanners all read and write that single directory rather than re-extracting a
multi-hundred-MB apk per command. Layout:

    <root>/
      workspace.json   marker: schema, dumpa + tool versions, input path/sha256/size/type
      app.apk          the canonical single apk (merged output for xapk; input for apk)
      extracted/       raw zip extract of app.apk (lib/, assets/, dex, manifest, arsc)
      dumps/           il2cpp and future per-tool outputs
      reports/         reserved for the Phase 2 report model

A workspace has two lifetimes: persistent (a path the caller named) or ephemeral (a
temp dir wiped on exit, honoring DUMPA_KEEP_TMP) — same primitive, so a command
behaves identically whether or not the user asked to keep the artifacts.
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, cast

from dumpa import __version__
from dumpa.core.errors import DumpaError
from dumpa.core.fs import create_or_recreate_dir, is_windows, windows_hide_file

const_workspace_schema_version = 1
const_file_workspace_meta = "workspace.json"
const_dir_extracted = "extracted"
const_dir_dumps = "dumps"
const_dir_reports = "reports"
const_dir_cache = "cache"
const_dir_smali = "smali"
const_dir_decompiled = "decompiled"
const_dir_native = "native"
const_dir_dex = "dex"
const_dir_playstore = "playstore"
const_file_app_apk = "app.apk"
const_file_gametype = "gametype.json"
const_file_xref = "xref.json"


def _empty_str_map() -> dict[str, str]:
    """Typed default factory for str->str maps (keeps inference concrete)."""
    return {}


@dataclass(frozen=True)
class WorkspaceMeta:
    """The workspace marker: enough to tie findings to one exact input and toolset."""
    schema_version: int
    dumpa_version: str
    input_path: str
    input_sha256: str
    input_size: int
    input_type: str                      # 'apk' | 'xapk'
    created: str                         # ISO-8601 UTC
    tool_versions: dict[str, str] = field(default_factory=_empty_str_map)
    build_options: dict[str, str] = field(default_factory=_empty_str_map)


def make_meta(*, input_path: Path, input_sha256: str, input_size: int,
              input_type: str, tool_versions: dict[str, str],
              build_options: dict[str, str] | None = None) -> WorkspaceMeta:
    """Build a WorkspaceMeta stamped with the current dumpa version and UTC time."""
    return WorkspaceMeta(
        schema_version=const_workspace_schema_version,
        dumpa_version=__version__,
        input_path=str(input_path),
        input_sha256=input_sha256,
        input_size=input_size,
        input_type=input_type,
        created=datetime.datetime.now(datetime.UTC).isoformat(),
        tool_versions=tool_versions,
        build_options=dict(build_options or {}),
    )


@dataclass(frozen=True)
class Workspace:
    """A located workspace directory plus typed accessors for its contents."""
    root: Path
    ephemeral: bool = False

    @property
    def app_apk(self) -> Path:
        return self.root / const_file_app_apk

    @property
    def extracted_dir(self) -> Path:
        return self.root / const_dir_extracted

    @property
    def smali_dir(self) -> Path:
        """apktool decode tree (smali/ + res/ + manifest); produced by `dumpa unpack --decode`."""
        return self.root / const_dir_smali

    def has_smali(self) -> bool:
        """True when the apktool decode tree exists and has content."""
        return self.smali_dir.is_dir() and any(self.smali_dir.iterdir())

    @property
    def decompiled_dir(self) -> Path:
        """JADX read-only decompile output (decompiled/); produced by `dumpa decompile`."""
        return self.root / const_dir_decompiled

    @property
    def dumps_dir(self) -> Path:
        return self.root / const_dir_dumps

    @property
    def reports_dir(self) -> Path:
        return self.root / const_dir_reports

    @property
    def cache_dir(self) -> Path:
        """Per-scanner derived-finding cache (cache/scanners/<name>.json)."""
        return self.root / const_dir_cache

    @property
    def native_dir(self) -> Path:
        """Per-library native symbol/section sidecars (dumps/native/)."""
        return self.dumps_dir / const_dir_native

    @property
    def dex_dir(self) -> Path:
        """Per-dex class/method/field inventory sidecars (dumps/dex/)."""
        return self.dumps_dir / const_dir_dex

    @property
    def xref_sidecar(self) -> Path:
        """Cross-reference index artifact (dumps/xref.json), built by `dumpa xref`."""
        return self.dumps_dir / const_file_xref

    @property
    def gametype_sidecar(self) -> Path:
        """Resolved game-type cache shared by the gametype + dumpcs scanners (dumps/gametype.json)."""
        return self.dumps_dir / const_file_gametype

    @property
    def playstore_cache_dir(self) -> Path:
        """Cached Play store listings, keyed by package (cache/playstore/)."""
        return self.cache_dir / const_dir_playstore

    @property
    def meta_path(self) -> Path:
        return self.root / const_file_workspace_meta

    def read_meta(self) -> WorkspaceMeta | None:
        """Load and validate workspace.json; None if absent or unreadable/invalid."""
        if not self.meta_path.is_file():
            return None
        try:
            with self.meta_path.open(encoding='UTF-8') as f:
                loaded = json.load(f)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(loaded, dict):
            return None
        data = cast("dict[str, Any]", loaded)
        try:
            return WorkspaceMeta(
                schema_version=int(data['schema_version']),
                dumpa_version=str(data['dumpa_version']),
                input_path=str(data['input_path']),
                input_sha256=str(data['input_sha256']),
                input_size=int(data['input_size']),
                input_type=str(data['input_type']),
                created=str(data['created']),
                tool_versions={str(k): str(v) for k, v in dict(data.get('tool_versions', {})).items()},
                build_options={str(k): str(v) for k, v in dict(data.get('build_options', {})).items()},
            )
        except (KeyError, TypeError, ValueError):
            return None

    def write_meta(self, meta: WorkspaceMeta) -> None:
        """Serialize the marker to workspace.json."""
        with self.meta_path.open('w', encoding='UTF-8') as f:
            json.dump(asdict(meta), f, indent=2, sort_keys=True)
            f.write('\n')

    def is_populated(self) -> bool:
        """True when the marker is present and the extracted tree has content."""
        if self.read_meta() is None:
            return False
        return self.extracted_dir.is_dir() and any(self.extracted_dir.iterdir())

    def prepare_build(self) -> None:
        """Clear stale app.apk/extracted/dumps and recreate empty extracted+dumps dirs."""
        self.root.mkdir(parents=True, exist_ok=True)
        if self.app_apk.exists():
            self.app_apk.unlink()
        if self.meta_path.exists():
            self.meta_path.unlink()
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir, ignore_errors=True)
        create_or_recreate_dir(self.extracted_dir)
        create_or_recreate_dir(self.dumps_dir)


def decide_reuse(ws: Workspace, input_sha256: str, *, force: bool,
                 build_options: dict[str, str] | None = None) -> bool:
    """Decide whether an existing workspace can be reused for this input.

    Returns True to reuse the existing extraction, False to (re)build. Raises when
    reuse would be unsafe and was not explicitly overridden:
      - sha256 mismatch without --force  -> refuse (wrong input for this workspace)
      - non-empty dir that is not a dumpa workspace -> refuse (don't clobber)
    """
    meta = ws.read_meta()
    if force:
        return False
    if meta is None:
        if ws.root.exists() and any(ws.root.iterdir()):
            raise DumpaError(
                f"{ws.root} exists and is not a dumpa workspace; "
                f"choose an empty directory or pass --force"
            )
        return False
    if meta.input_sha256 != input_sha256:
        raise DumpaError(
            f"workspace {ws.root} was built from a different input "
            f"(sha256 mismatch); pass --force to rebuild"
        )
    if build_options is not None and meta.build_options != build_options:
        raise DumpaError(
            f"workspace {ws.root} was built with different build options; "
            f"pass --force to rebuild"
        )
    return ws.is_populated()


@contextmanager
def open_workspace(path: Path | None) -> Generator[Workspace]:
    """Yield a Workspace. path=None -> ephemeral temp dir (wiped on exit); else persistent.

    Ephemeral dirs honor DUMPA_KEEP_TMP=1 (retain for debugging), matching the
    behaviour of the convert pipeline's private tmp dir.
    """
    if path is None:
        parent = Path.cwd()
        tmp = Path(tempfile.mkdtemp(prefix='.dumpa.ws.', dir=str(parent))).resolve()
        if is_windows():
            windows_hide_file(tmp)
        keep = os.environ.get('DUMPA_KEEP_TMP', '') == '1'
        try:
            yield Workspace(root=tmp, ephemeral=True)
        finally:
            if not keep and tmp.exists():
                shutil.rmtree(tmp, ignore_errors=True)
        return

    root = path.resolve()
    root.mkdir(parents=True, exist_ok=True)
    yield Workspace(root=root, ephemeral=False)
