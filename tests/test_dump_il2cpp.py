"""dump-il2cpp workspace side effects."""

from __future__ import annotations

from dumpa.commands.dump_il2cpp import _invalidate_report
from dumpa.core.workspace import Workspace


def test_invalidate_report_removes_report_json(tmp_path) -> None:
    ws = Workspace(root=tmp_path / "ws")
    report = ws.reports_dir / "report.json"
    report.parent.mkdir(parents=True)
    report.write_text("{}", encoding="UTF-8")

    _invalidate_report(ws)

    assert not report.exists()


def test_invalidate_report_missing_is_ok(tmp_path) -> None:
    _invalidate_report(Workspace(root=tmp_path / "ws"))
