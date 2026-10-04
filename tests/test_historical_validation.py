#!/usr/bin/env python3
"""Tests for bounded historical validation closed-loop."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_historical_pivots.py"


def _write_pivot(rd, classification, url, path=None):
    row = {
        "schema": "bugbountyci.historical_pivot.v1",
        "classification": classification,
        "url": url,
        "path": path or "/",
        "historical_source": "wayback.txt",
        "current_host_relation": True,
    }
    p = rd / "info_disclosure" / "historical_pivots.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(json.dumps(row) + "\n")


def test_already_known_not_run(tmp_path):
    rd = tmp_path / "results"
    (rd / "urls").mkdir(parents=True)
    (rd / "live").mkdir(parents=True)
    (rd / "urls" / "all.txt").write_text("https://app.example.com/api/export\n")
    (rd / "live" / "live.txt").write_text("https://app.example.com\n")
    _write_pivot(rd, "HISTORICAL_PATH_CURRENT_HOST", "https://app.example.com/api/export", "/api/export")
    subprocess.check_call([sys.executable, str(SCRIPT), "--results-dir", str(rd), "--budget", "5"])
    rows = [json.loads(l) for l in open(rd / "info_disclosure" / "historical_validations.jsonl") if l.strip()]
    assert rows[0]["outcome"] == "NOT_RUN"
    assert rows[0]["not_run_reason"] == "already_in_current_url_corpus"
    print("  OK already_known")


def test_budget_and_dedup(tmp_path):
    rd = tmp_path / "results"
    (rd / "urls").mkdir(parents=True)
    (rd / "live").mkdir(parents=True)
    (rd / "urls" / "all.txt").write_text("https://app.example.com/\n")
    (rd / "live" / "live.txt").write_text("https://app.example.com\n")
    for i in range(3):
        _write_pivot(rd, "HISTORICAL_PATH_CURRENT_HOST", f"https://app.example.com/old{i}", f"/old{i}")
    # duplicate path/host second time
    _write_pivot(rd, "HISTORICAL_PATH_CURRENT_HOST", "https://app.example.com/old0", "/old0")
    subprocess.check_call([sys.executable, str(SCRIPT), "--results-dir", str(rd), "--budget", "1", "--dry-run"])
    rows = [json.loads(l) for l in open(rd / "info_disclosure" / "historical_validations.jsonl") if l.strip()]
    outcomes = [r["outcome"] for r in rows]
    assert "NOT_RUN" in outcomes
    print("  OK budget/dedup dry-run", len(rows))


def test_outcome_classifier_unit():
    sys.path.insert(0, str(ROOT / "scripts"))
    # import by path
    import importlib.util
    spec = importlib.util.spec_from_file_location("vh", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.classify_outcome({"status": 200, "error": None}) == "CURRENTLY_REACHABLE"
    assert mod.classify_outcome({"status": 404, "error": None}) == "CURRENTLY_UNREACHABLE"
    assert mod.classify_outcome({"status": 302, "error": None}) == "REDIRECTED"
    assert mod.classify_outcome({"status": 403, "error": None}) == "BLOCKED_OR_RATE_LIMITED"
    assert mod.classify_outcome({"status": 429, "error": None}) == "BLOCKED_OR_RATE_LIMITED"
    assert mod.classify_outcome({"status": 0, "error": "Timeout"}) == "VALIDATION_ERROR"
    assert mod.classify_outcome({"status": 500, "error": None}) == "VALIDATION_ERROR"
    print("  OK outcome classifier")


def test_hunter_loads_only_actionable(tmp_path):
    sys.path.insert(0, str(ROOT))
    from pipeline.detection.hunter_queue_builder import load_historical_validations
    rd = tmp_path / "results"
    idir = rd / "info_disclosure"
    idir.mkdir(parents=True)
    rows = [
        {"outcome": "CURRENTLY_REACHABLE", "validation_url": "https://a/x", "status": 200, "historical_source": "wayback"},
        {"outcome": "CURRENTLY_UNREACHABLE", "validation_url": "https://a/y", "status": 404},
        {"outcome": "NOT_RUN", "validation_url": "https://a/z", "not_run_reason": "budget"},
        {"outcome": "REDIRECTED", "validation_url": "https://a/r", "status": 301, "location": "https://a/login"},
    ]
    (idir / "historical_validations.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    entries = load_historical_validations(str(rd))
    assert len(entries) == 2
    assert all(e["engine"] == "historical_pivot" for e in entries)
    print("  OK hunter intake filters")


if __name__ == "__main__":
    import tempfile
    test_outcome_classifier_unit()
    with tempfile.TemporaryDirectory() as td:
        test_already_known_not_run(Path(td) / "a")
    with tempfile.TemporaryDirectory() as td:
        test_budget_and_dedup(Path(td) / "b")
    with tempfile.TemporaryDirectory() as td:
        test_hunter_loads_only_actionable(Path(td) / "c")
    print("all passed")
