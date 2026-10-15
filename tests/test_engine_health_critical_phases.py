"""engine_health.overall must degrade on critical phase errors and metrics integrity."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run_exports(rd: Path) -> dict:
    env = os.environ.copy()
    env["TARGET"] = "example.com"
    env["TIMESTAMP"] = "test"
    subprocess.check_call(
        [sys.executable, str(ROOT / "scripts" / "write_pipeline_exports.py"), str(rd)],
        env=env,
    )
    return json.loads((rd / "meta" / "engine_health.json").read_text())


def test_smart_fuzzing_error_degrades_overall(tmp_path: Path):
    (tmp_path / "meta" / "phases").mkdir(parents=True)
    (tmp_path / "meta" / "phases" / "smart_fuzzing.json").write_text(
        json.dumps(
            {
                "phase": "smart_fuzzing",
                "status": "error",
                "detail": "state=FFUF_PARSE_FAILURE parse_failures=2",
            }
        )
    )
    eng = _run_exports(tmp_path)
    assert eng["overall"] == "DEGRADED"
    assert any("smart_fuzzing" in f for f in eng["flags"])


def test_access_control_error_degrades_overall(tmp_path: Path):
    (tmp_path / "meta" / "phases").mkdir(parents=True)
    (tmp_path / "meta" / "phases" / "access_control.json").write_text(
        json.dumps(
            {
                "phase": "access_control",
                "status": "error",
                "detail": "malformed response_diffs.json",
            }
        )
    )
    eng = _run_exports(tmp_path)
    assert eng["overall"] == "DEGRADED"
    assert any("access_control" in f for f in eng["flags"])


def test_empty_phase_does_not_degrade(tmp_path: Path):
    (tmp_path / "meta" / "phases").mkdir(parents=True)
    (tmp_path / "meta" / "phases" / "ssrf.json").write_text(
        json.dumps(
            {
                "phase": "ssrf",
                "status": "empty",
                "detail": "0 candidates",
            }
        )
    )
    eng = _run_exports(tmp_path)
    assert eng["overall"] == "OK"
    assert not any("ssrf phase=empty" in f for f in eng["flags"])


def test_detection_metrics_untrusted_degrades(tmp_path: Path):
    (tmp_path / "meta" / "phases").mkdir(parents=True)
    (tmp_path / "detection").mkdir(parents=True)
    (tmp_path / "detection" / "metrics.json").write_text(
        json.dumps(
            {
                "engines": {},
                "overall": {"total_evidence": 0},
                "input_integrity": {
                    "engine_results": "malformed",
                    "response_diffs": "ok",
                    "issues": ["engine_results:malformed"],
                    "trusted": False,
                },
            }
        )
    )
    eng = _run_exports(tmp_path)
    assert eng["overall"] == "DEGRADED"
    assert any("detection_metrics" in f for f in eng["flags"])


def test_malformed_phase_file_flagged(tmp_path: Path):
    (tmp_path / "meta" / "phases").mkdir(parents=True)
    (tmp_path / "meta" / "phases" / "broken.json").write_text("{not json")
    eng = _run_exports(tmp_path)
    assert eng["overall"] == "DEGRADED"
    assert eng.get("phase_load_issues")
