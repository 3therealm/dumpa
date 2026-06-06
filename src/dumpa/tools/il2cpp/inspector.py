"""Il2CppInspector engine.

Invocation targets the Il2CppInspector CLI form:
    <tool> -i <binary> -m <metadata> --cs-out <out_dir>/dump.cs
Il2CppInspector can emit many formats (IDA/Ghidra/JSON); this wires C# output, which
is the common case. The tool is a .NET program; expose it on PATH (or via [tools]
il2cppinspector) as a launcher that already includes any required `dotnet` prefix.
"""

from __future__ import annotations

import logging
from pathlib import Path

from dumpa.core.errors import DumpaError
from dumpa.core.process import run
from dumpa.core.tools import ResolvedTool
from dumpa.tools.il2cpp import Il2CppInputs, Il2CppResult

logger = logging.getLogger("dumpa")


class Il2CppInspectorEngine:
    name = 'inspector'
    tool_name = 'il2cppinspector'

    def dump(self, tool: ResolvedTool, inputs: Il2CppInputs, out_dir: Path) -> Il2CppResult:
        out_dir.mkdir(parents=True, exist_ok=True)
        cs_out = out_dir / 'dump.cs'
        # out_dir may be reused; drop a stale dump.cs so the existence check below
        # reflects this run rather than a prior one.
        if cs_out.exists():
            cs_out.unlink()
        run(tool.argv('-i', str(inputs.binary), '-m', str(inputs.metadata), '--cs-out', str(cs_out)),
            fail_msg='Il2CppInspector failed')
        artifacts = {'dump_cs': cs_out} if cs_out.exists() else {}
        if not artifacts:
            raise DumpaError("Il2CppInspector produced no output")
        return Il2CppResult(engine=self.name, out_dir=out_dir, artifacts=artifacts)
