"""iter_method_sigs / method_set: stable, address-free method identities from dump.cs."""

from __future__ import annotations

from pathlib import Path

from dumpa.core.dumpcs_methods import method_set

_V1 = """\
// Namespace: Game
public class GameManager : MonoBehaviour
{
\t// Fields
\tprivate int hp;

\t// Methods
\t// RVA: 0x1000 Offset: 0x1000 VA: 0x1000
\tpublic void SpawnEnemy() { }
\t// RVA: 0x2000 Offset: 0x2000 VA: 0x2000
\tpublic Int32 get_Score() { }
}
"""

# Same get_Score but at a DIFFERENT RVA; SpawnEnemy gains a param; NewMethod added.
_V2 = """\
// Namespace: Game
public class GameManager : MonoBehaviour
{
\tprivate int hp;

\t// RVA: 0x9999 Offset: 0x9999 VA: 0x9999
\tpublic void SpawnEnemy(Int32 count) { }
\t// RVA: 0x2500 Offset: 0x2500 VA: 0x2500
\tpublic Int32 get_Score() { }
\t// RVA: 0x3000 Offset: 0x3000 VA: 0x3000
\tpublic void NewMethod() { }
}
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_methods_are_namespaced_and_addressless(tmp_path: Path) -> None:
    s = method_set(_write(tmp_path, "a.cs", _V1))
    assert "Game.GameManager::public void SpawnEnemy()" in s
    assert "Game.GameManager::public Int32 get_Score()" in s
    # fields are not methods
    assert not any("hp" in m for m in s)
    # no RVA/offset bleeds into the identity
    assert not any("RVA" in m or "0x" in m for m in s)


def test_rva_only_change_does_not_diff(tmp_path: Path) -> None:
    s1 = method_set(_write(tmp_path, "a.cs", _V1))
    s2 = method_set(_write(tmp_path, "b.cs", _V2))
    added = s2 - s1
    removed = s1 - s2
    # get_Score moved RVA but is otherwise identical -> must not appear in either side
    assert not any("get_Score" in m for m in added | removed)
    assert "Game.GameManager::public void NewMethod()" in added
    assert "Game.GameManager::public void SpawnEnemy(Int32 count)" in added
    assert "Game.GameManager::public void SpawnEnemy()" in removed


def test_method_before_type_is_dropped(tmp_path: Path) -> None:
    text = "\tpublic void Orphan() { }\npublic class C\n{\n\tpublic void Real() { }\n}\n"
    s = method_set(_write(tmp_path, "c.cs", text))
    assert "C::public void Real()" in s
    assert not any("Orphan" in m for m in s)
