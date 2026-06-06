"""Il2CppDumper engine.

Invocation targets the standard Il2CppDumper CLI form:
    <tool> <binary> <metadata> <output_dir>
which emits dump.cs, script.json, il2cpp.h, and friends into output_dir. The tool is
a .NET program; expose it on PATH (or via [tools] il2cppdumper) as a launcher that
already includes any required `dotnet` prefix.
"""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.core.errors import DumpaError, ToolExecutionError
from dumpa.core.process import run
from dumpa.core.tools import ResolvedTool
from dumpa.tools.il2cpp import Il2CppInputs, Il2CppResult

logger = logging.getLogger("dumpa")

_ARTIFACTS = (
    ('dump_cs', 'dump.cs'),
    ('script_json', 'script.json'),
    ('header', 'il2cpp.h'),
    ('stringliteral', 'stringliteral.json'),
    ('dummydll', 'DummyDll'),
)


class Il2CppDumperEngine:
    name = 'dumper'
    tool_name = 'il2cppdumper'

    def dump(self, tool: ResolvedTool, inputs: Il2CppInputs, out_dir: Path) -> Il2CppResult:
        out_dir.mkdir(parents=True, exist_ok=True)
        dump_cs = out_dir / 'dump.cs'
        try:
            run(tool.argv(str(inputs.binary), str(inputs.metadata), str(out_dir)),
                fail_msg='Il2CppDumper failed')
        except ToolExecutionError:
            # Il2CppDumper writes all output, then crashes on its interactive
            # "Press any key to exit" prompt when stdin is not a TTY. Tolerate the
            # non-zero exit only when the dump actually landed.
            if not dump_cs.exists():
                raise
            logger.warning("Il2CppDumper exited non-zero (interactive exit prompt); output present, continuing")
        artifacts = {key: out_dir / fname for key, fname in _ARTIFACTS if (out_dir / fname).exists()}
        if 'dump_cs' not in artifacts:
            raise DumpaError("Il2CppDumper produced no dump.cs")
        return Il2CppResult(engine=self.name, out_dir=out_dir, artifacts=artifacts)
