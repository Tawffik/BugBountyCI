"""Malformed engine_results / response_diffs must not look like empty success."""
from __future__ import annotations

import json
from pathlib import Path

from pipeline.detection.metrics_builder import build_metrics, load_engine_results


def test_missing_engine_results_is_missing_not_malformed(tmp_path: Path):
    rows, status = load_engine_results(str(tmp_path))
    assert rows == []
    assert status == "missing"


def test_malformed_engine_results_flagged(tmp_path: Path):
    det = tmp_path / "detection"
    det.mkdir()
    (det / "engine_results.json").write_text("{not-json")
    rows, status = load_engine_results(str(tmp_path))
    assert rows == []
    assert status == "malformed"
    m = build_metrics(str(tmp_path))
    assert m["input_integrity"]["engine_results"] == "malformed"
    assert m["input_integrity"]["trusted"] is False
    assert "engine_results:malformed" in m["input_integrity"]["issues"]


def test_malformed_response_diffs_flagged(tmp_path: Path):
    sf = tmp_path / "smart-fuzzing"
    sf.mkdir()
    (sf / "response_diffs.json").write_text("truncated")
    m = build_metrics(str(tmp_path))
    assert m["input_integrity"]["response_diffs"] == "malformed"
    assert m["input_integrity"]["trusted"] is False


def test_valid_empty_list_is_trusted(tmp_path: Path):
    det = tmp_path / "detection"
    det.mkdir()
    (det / "engine_results.json").write_text("[]")
    sf = tmp_path / "smart-fuzzing"
    sf.mkdir()
    (sf / "response_diffs.json").write_text("[]")
    m = build_metrics(str(tmp_path))
    assert m["input_integrity"]["trusted"] is True
    assert m["overall"]["total_evidence"] == 0


def test_single_engine_object_accepted(tmp_path: Path):
    det = tmp_path / "detection"
    det.mkdir()
    (det / "engine_results.json").write_text(
        json.dumps(
            {
                "engine": "ssrf-v1",
                "ran": True,
                "error": None,
                "candidates_generated": 0,
                "evidence": [],
            }
        )
    )
    rows, status = load_engine_results(str(tmp_path))
    assert status == "ok"
    assert len(rows) == 1
