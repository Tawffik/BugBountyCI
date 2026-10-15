"""pipeline_health.md producer must surface critical phase errors."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _mod():
    path = ROOT / "scripts" / "collect_phase_integrity_flags.py"
    spec = importlib.util.spec_from_file_location("collect_phase_integrity_flags", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_smart_fuzzing_error_produces_flag(tmp_path: Path):
    phases = tmp_path / "meta" / "phases"
    phases.mkdir(parents=True)
    (phases / "smart_fuzzing.json").write_text(
        json.dumps({"phase": "smart_fuzzing", "status": "error", "detail": "FFUF_PARSE_FAILURE"})
    )
    flags = _mod().collect_phase_integrity_flags(str(tmp_path))
    assert any("smart_fuzzing" in f and "error" in f.lower() for f in flags)


def test_empty_phase_does_not_flag(tmp_path: Path):
    phases = tmp_path / "meta" / "phases"
    phases.mkdir(parents=True)
    (phases / "ssrf.json").write_text(
        json.dumps({"phase": "ssrf", "status": "empty", "detail": "0 candidates"})
    )
    flags = _mod().collect_phase_integrity_flags(str(tmp_path))
    assert flags == []


def test_malformed_phase_file_flagged(tmp_path: Path):
    phases = tmp_path / "meta" / "phases"
    phases.mkdir(parents=True)
    (phases / "access_control.json").write_text("{not-json")
    flags = _mod().collect_phase_integrity_flags(str(tmp_path))
    assert any("malformed" in f.lower() for f in flags)
