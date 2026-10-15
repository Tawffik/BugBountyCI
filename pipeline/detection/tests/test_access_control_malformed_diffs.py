"""Malformed response_diffs must yield engine error, not EMPTY_VALID."""
from __future__ import annotations

from pathlib import Path

from pipeline.detection.access_control_engine import AccessControlEngine
from pipeline.detection.engine import run_engine, result_to_phase_status


def test_malformed_response_diffs_is_error_phase(tmp_path: Path):
    sf = tmp_path / "smart-fuzzing"
    sf.mkdir()
    (sf / "response_diffs.json").write_text("{not-json")
    eng = AccessControlEngine(results_dir=str(tmp_path), prober=lambda u: None)
    r = run_engine(eng, target_profile={}, vocabulary={})
    status, detail = result_to_phase_status(r)
    assert r.ran is False
    assert r.error
    assert status == "error"
    assert "malformed" in (r.error or "").lower() or "malformed" in detail.lower()
