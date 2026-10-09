import json
import os
import subprocess
import tempfile
from pathlib import Path


def test_enriches_missing_phases_from_summaries():
    td = Path(tempfile.mkdtemp())
    (td / "meta" / "phases").mkdir(parents=True)
    (td / "info_disclosure").mkdir(parents=True)
    (td / "meta" / "pipeline_health.md").write_text(
        "## Overall: 🟢 HEALTHY\n\n_No anomalies detected in the funnel._\n"
    )
    (td / "info_disclosure" / "historical_validation_summary.json").write_text(
        json.dumps(
            {
                "validated": 40,
                "not_run": 63,
                "outcomes": {"REDIRECTED": 40},
            }
        )
    )
    (td / "info_disclosure" / "representation_summary.json").write_text(
        json.dumps(
            {
                "candidates": 1,
                "pairs_run": 1,
                "kinds": {"NETWORK_ERROR": 1},
                "diagnosis": "CANDIDATES_SELECTED",
            }
        )
    )
    (td / "info_disclosure" / "historical_pivot_summary.json").write_text(
        json.dumps({"total": 144, "counts": {"STILL_LIVE": 41}})
    )
    r = subprocess.run(
        ["python3", "scripts/write_pipeline_exports.py", str(td)],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    eh = json.loads((td / "meta" / "engine_health.json").read_text())
    assert "historical_validation" in eh["phases"]
    assert "representation_differential" in eh["phases"]
    assert "historical_pivot" in eh["phases"]
    assert "validated=40" in eh["phases"]["historical_validation"]["detail"]
