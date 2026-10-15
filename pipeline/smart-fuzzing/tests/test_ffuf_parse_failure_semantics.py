"""#31 follow-up: parse failures must alter pipeline_state, not only a counter."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DIFF = ROOT / "pipeline" / "smart-fuzzing" / "response_diff.py"


def _run_diff(tmp: Path, ffuf_dir: Path) -> dict:
    rd = tmp / "results"
    (rd / "smart-fuzzing").mkdir(parents=True)
    (rd / "smart-fuzzing" / "baseline.json").write_text("{}")
    subprocess.check_call(
        [
            sys.executable,
            str(DIFF),
            "--results-dir",
            str(rd),
            "--ffuf-json-dir",
            str(ffuf_dir),
        ]
    )
    metrics = json.loads((rd / "smart-fuzzing" / "metrics.json").read_text())
    outcome = json.loads((rd / "smart-fuzzing" / "strategy_outcome.json").read_text())
    ranking = json.loads((rd / "smart-fuzzing" / "response_ranking.json").read_text())
    return {"metrics": metrics, "outcome": outcome, "ranking": ranking}


def test_all_malformed_json_is_parse_failure_not_no_output(tmp_path: Path):
    ffuf = tmp_path / "ffuf"
    ffuf.mkdir()
    (ffuf / "host1.json").write_text("{not json")
    (ffuf / "host2.json").write_text("truncated...")
    r = _run_diff(tmp_path, ffuf)
    assert r["metrics"]["ffuf_json_parse_failures"] >= 2
    assert r["metrics"]["pipeline_state"] == "FFUF_PARSE_FAILURE"
    assert r["outcome"]["pipeline_state"] == "FFUF_PARSE_FAILURE"
    assert r["ranking"]["pipeline_state"] == "FFUF_PARSE_FAILURE"
    assert r["ranking"]["ffuf_json_parse_failures"] >= 2


def test_mixed_valid_and_malformed_is_partial(tmp_path: Path):
    ffuf = tmp_path / "ffuf"
    ffuf.mkdir()
    (ffuf / "bad.json").write_text("{broken")
    good = {
        "config": {"url": "https://app.example.com/FUZZ"},
        "results": [{"url": "https://app.example.com/admin", "status": 200, "length": 100}],
    }
    (ffuf / "good.json").write_text(json.dumps(good))
    r = _run_diff(tmp_path, ffuf)
    assert r["metrics"]["ffuf_json_parse_failures"] >= 1
    assert r["metrics"]["pipeline_state"] in (
        "PARTIAL_FFUF_PARSE",
        "DIFFS_GENERATED_PARTIAL_PARSE",
        "NO_DIFFERENTIAL_SIGNAL",  # may classify as UNKNOWN without baseline
    )
    # Must not claim clean NO_FFUF_OUTPUT or pure REQUESTS_EXECUTED_NO_MATCH when parses failed
    assert r["metrics"]["pipeline_state"] not in ("NO_FFUF_OUTPUT",)
    assert r["metrics"]["ffuf"]["ffuf_json_parse_failures"] >= 1


def test_empty_dir_is_no_ffuf_output(tmp_path: Path):
    ffuf = tmp_path / "ffuf"
    ffuf.mkdir()
    r = _run_diff(tmp_path, ffuf)
    assert r["metrics"]["pipeline_state"] == "NO_FFUF_OUTPUT"
    assert r["metrics"]["ffuf_json_parse_failures"] == 0


def test_valid_zero_results_is_no_match_not_parse_failure(tmp_path: Path):
    ffuf = tmp_path / "ffuf"
    ffuf.mkdir()
    (ffuf / "empty.json").write_text(
        json.dumps({"config": {"url": "https://app.example.com/FUZZ"}, "results": []})
    )
    r = _run_diff(tmp_path, ffuf)
    assert r["metrics"]["ffuf_json_parse_failures"] == 0
    assert r["metrics"]["pipeline_state"] == "REQUESTS_EXECUTED_NO_MATCH"
