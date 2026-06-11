"""Native-symbol matcher: match rule bundles against parsed ELF symbol names.

Unlike the `content` matcher (which finds a symbol *string* anywhere in a `.so`), this
scanner tests rule regexes against the real `.dynsym`/`.symtab` symbol tables, so a hit
distinguishes an exported function from an incidental `.rodata` string and carries the
export's RVA. It consumes the per-library sidecars `native.scan` already wrote under
`dumps/native/` (falling back to a direct `core.elf.parse_elf` for any lib without one),
then runs them through `rules.match_symbol_rules`. Fail-soft: a bad/missing sidecar or
unparsable lib is skipped, never fatal.
"""

from __future__ import annotations

import json
import logging

from dumpa.core.elf import parse_elf
from dumpa.core.report import Finding
from dumpa.core.rules import NativeSymbols, load_builtin, match_symbol_rules
from dumpa.core.workspace import Workspace

logger = logging.getLogger("dumpa")

const_symbol_bundle = "native_symbols"


def _from_sidecar(path) -> NativeSymbols | None:
    try:
        payload = json.loads(path.read_text(encoding="UTF-8"))
        abi = str(payload["abi"])
        lib = str(payload["lib"])
        exports = tuple((str(e["name"]), int(e["rva"])) for e in payload.get("exports", []))
        imports = tuple(str(i["name"]) for i in payload.get("imports", []))
    except (OSError, ValueError, KeyError, TypeError):
        logger.debug("could not read native sidecar %s", path, exc_info=True)
        return None
    return NativeSymbols(rel_path=f"lib/{abi}/{lib}", abi=abi, exports=exports, imports=imports)


def _from_elf(so) -> NativeSymbols | None:
    elf = parse_elf(so)
    if elf is None:
        return None
    abi = so.parent.name
    exports = tuple((s.name, s.value) for s in elf.exports)
    imports = tuple(s.name for s in elf.imports)
    return NativeSymbols(rel_path=f"lib/{abi}/{so.name}", abi=abi, exports=exports, imports=imports)


def scan(ws: Workspace) -> list[Finding]:
    """Match the native-symbols bundle against every lib/<abi>/*.so symbol table."""
    ex = ws.extracted_dir
    if not ex.is_dir():
        return []
    bundle = load_builtin(const_symbol_bundle)
    symbol_rules = [r for r in bundle.rules if r.is_symbol]
    if not symbol_rules:
        return []

    libs: list[NativeSymbols] = []
    for so in sorted(ex.glob("lib/*/*.so")):
        abi, name = so.parent.name, so.name
        sidecar = ws.native_dir / f"{abi}__{name}.json"
        lib = _from_sidecar(sidecar) if sidecar.is_file() else _from_elf(so)
        if lib is not None:
            libs.append(lib)
    return match_symbol_rules(symbol_rules, bundle, libs)
