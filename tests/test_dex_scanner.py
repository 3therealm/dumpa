"""DEX inventory scanner + the dex-location enrich pass."""

from __future__ import annotations

from pathlib import Path

from _dex_build import build_dex

from dumpa import scanners
from dumpa.core.dex import DexFile
from dumpa.core.report import Confidence, Finding, Location
from dumpa.core.workspace import Workspace
from dumpa.scanners import dex as dex_scanner
from dumpa.scanners import enrich_dex_locations


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.extracted_dir.mkdir(parents=True)
    return ws


# --- inventory scanner -------------------------------------------------------

def test_dex_finding_and_sidecar(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    data, _ = build_dex()
    (ws.extracted_dir / "classes.dex").write_bytes(data)
    findings = dex_scanner.scan(ws)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "dex"
    assert f.subject == "classes.dex"
    assert f.attributes["class_count"] == "1"
    assert f.attributes["method_count"] == "1"
    assert f.attributes["field_count"] == "1"
    sidecar = ws.root / f.attributes["sidecar"]
    assert sidecar.is_file()


def test_dex_scanner_skips_non_dex(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.extracted_dir / "classes.dex").write_bytes(b"not a dex file, padding padding")
    assert dex_scanner.scan(ws) == []


def test_dex_scanner_multidex(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    data, _ = build_dex()
    (ws.extracted_dir / "classes.dex").write_bytes(data)
    (ws.extracted_dir / "classes2.dex").write_bytes(data)
    findings = dex_scanner.scan(ws)
    assert {f.subject for f in findings} == {"classes.dex", "classes2.dex"}


# --- enrich pass -------------------------------------------------------------

def test_enrich_backfills_class_from_descriptor(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    data, info = build_dex()
    (ws.extracted_dir / "classes.dex").write_bytes(data)
    start, _ = info["str_content"]["Lcom/x/A;"]
    finding = Finding(kind="tracker", subject="acme", confidence=Confidence.MEDIUM,
                      locations=[Location(file_path="classes.dex", file_offset=start + 3)])
    out = enrich_dex_locations([finding], ws)
    loc = out[0].locations[0]
    assert loc.dex_class == "com.x.A"
    assert loc.dex_method is None


def test_enrich_backfills_method_from_code_offset(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    data, info = build_dex()
    (ws.extracted_dir / "classes.dex").write_bytes(data)
    finding = Finding(kind="secret", subject="x", confidence=Confidence.LOW,
                      locations=[Location(file_path="classes.dex",
                                          file_offset=info["code_off"] + 17)])
    out = enrich_dex_locations([finding], ws)
    loc = out[0].locations[0]
    assert loc.dex_class == "com.x.A"
    assert loc.dex_method == "foo"


def test_enrich_backfills_method_from_const_string_xref(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    data, info = build_dex()
    (ws.extracted_dir / "classes.dex").write_bytes(data)
    start, _ = info["str_content"][info["ref_const"]]   # loaded by foo's const-string
    finding = Finding(kind="secret", subject="token", confidence=Confidence.MEDIUM,
                      locations=[Location(file_path="classes.dex", file_offset=start)])
    out = enrich_dex_locations([finding], ws)
    loc = out[0].locations[0]
    assert loc.dex_class == "com.x.A"
    assert loc.dex_method == "foo"


def test_enrich_multi_referencer_adds_evidence(tmp_path: Path, monkeypatch) -> None:
    crafted = DexFile(version=35, classes=(), code_spans=(), desc_spans=(),
                      xref_spans=((100, 110, (("a.B", "m1"), ("c.D", "m2"))),))
    ws = _ws(tmp_path)
    (ws.extracted_dir / "classes.dex").write_bytes(b"placeholder")
    monkeypatch.setattr(scanners, "parse_dex", lambda _p: crafted)

    finding = Finding(kind="endpoint", subject="u", confidence=Confidence.LOW,
                      locations=[Location(file_path="classes.dex", file_offset=105)])
    out = enrich_dex_locations([finding], ws)
    # No single owner asserted on the location...
    assert out[0].locations[0].dex_method is None
    # ...but both referencers surfaced as evidence.
    ev = [e for e in out[0].evidence if e.tool == scanners.const_dex_xref_tool]
    assert len(ev) == 1
    assert "2 methods" in ev[0].description
    assert ev[0].snippet == "a.B#m1, c.D#m2"


def test_enrich_field_from_static_init(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    url = "https://k.example.com/cfg"
    data, info = build_dex(static_string=url)
    (ws.extracted_dir / "classes.dex").write_bytes(data)
    start, _ = info["str_content"][url]
    finding = Finding(kind="endpoint", subject=url, confidence=Confidence.LOW,
                      locations=[Location(file_path="classes.dex", file_offset=start)])
    out = enrich_dex_locations([finding], ws)
    loc = out[0].locations[0]
    assert loc.dex_field == "com.x.A.KEY"
    assert loc.dex_class == "com.x.A"          # derived from the field descriptor


def test_enrich_instruction_field_access(tmp_path: Path) -> None:
    import struct
    ws = _ws(tmp_path)
    insns = struct.pack("<HH", 0x0060, 0)      # sget v0, field@0 (com.x.A.bar)
    data, info = build_dex(insns=insns)
    (ws.extracted_dir / "classes.dex").write_bytes(data)
    finding = Finding(kind="protection", subject="p", confidence=Confidence.MEDIUM,
                      locations=[Location(file_path="classes.dex",
                                          file_offset=info["code_off"] + 16 + 1)])
    out = enrich_dex_locations([finding], ws)
    loc = out[0].locations[0]
    assert loc.dex_class == "com.x.A"
    assert loc.dex_method == "foo"
    assert loc.dex_field == "com.x.A.bar"
    assert loc.dex_bytecode_offset == 0
    ev = [e for e in out[0].evidence if e.tool == scanners.dex_instruction_tool]
    assert len(ev) == 1
    assert "0x60" in ev[0].description


def test_enrich_multi_field_init_adds_evidence(tmp_path: Path, monkeypatch) -> None:
    crafted = DexFile(version=35, classes=(), code_spans=(), desc_spans=(),
                      field_init_spans=((100, 110, ("a.B.X", "c.D.Y")),))
    ws = _ws(tmp_path)
    (ws.extracted_dir / "classes.dex").write_bytes(b"placeholder")
    monkeypatch.setattr(scanners, "parse_dex", lambda _p: crafted)

    finding = Finding(kind="secret", subject="k", confidence=Confidence.LOW,
                      locations=[Location(file_path="classes.dex", file_offset=105)])
    out = enrich_dex_locations([finding], ws)
    assert out[0].locations[0].dex_field is None        # no single owner asserted
    ev = [e for e in out[0].evidence if e.tool == scanners.dex_field_xref_tool]
    assert len(ev) == 1
    assert "2 static fields" in ev[0].description
    assert ev[0].snippet == "a.B.X, c.D.Y"


def test_enrich_leaves_plain_string_unresolved(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    data, info = build_dex()
    (ws.extracted_dir / "classes.dex").write_bytes(data)
    start, _ = info["str_content"]["hello"]
    finding = Finding(kind="secret", subject="k", confidence=Confidence.LOW,
                      locations=[Location(file_path="classes.dex", file_offset=start)])
    out = enrich_dex_locations([finding], ws)
    assert out[0].locations[0].dex_class is None
    assert out[0] is finding


def test_enrich_leaves_non_dex_findings(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    finding = Finding(kind="protection", subject="m", confidence=Confidence.HIGH,
                      locations=[Location(file_path="lib/arm64-v8a/x.so", file_offset=10)])
    out = enrich_dex_locations([finding], ws)
    assert out[0].locations[0].dex_class is None
    assert out[0] is finding


def test_enrich_preserves_existing_dex_class(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    data, info = build_dex()
    (ws.extracted_dir / "classes.dex").write_bytes(data)
    start, _ = info["str_content"]["Lcom/x/A;"]
    finding = Finding(kind="tracker", subject="acme", confidence=Confidence.MEDIUM,
                      locations=[Location(file_path="classes.dex", file_offset=start + 3,
                                          dex_class="already.Set")])
    out = enrich_dex_locations([finding], ws)
    assert out[0] is finding                       # untouched
