import json
import os
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.detection.hunter_queue_builder import (
    normalize_entry,
    render_markdown,
    load_cloud_exposure_findings,
    main,
)


def test_normalize_fills_priority_class():
    e = normalize_entry({"classification": "LEAD", "target": "https://x/", "reason": "t"})
    assert e["priority_class"] == "LEAD"
    assert e["engine"]


def test_render_survives_missing_priority_class():
    entries = [
        {"classification": "INTERESTING", "target": "https://a/", "reason": "x", "source": "cloud_exposure"},
        {"priority_class": "LEAD", "engine": "smart-403", "target": "https://b/", "reason": "y"},
    ]
    md = render_markdown(entries, "example.com")
    assert "Hunter Queue" in md
    assert len(md) > 50


def test_cloud_loader_sets_priority_class():
    with tempfile.TemporaryDirectory() as td:
        det = Path(td) / "detection"
        det.mkdir()
        row = {
            "final_disposition": "provider_clue",
            "asset_normalized": "https://storage.googleapis.com/t/",
            "host": "storage.googleapis.com",
            "provider_hypothesis": "gcs",
            "scope_disposition": "name_guess",
            "probe": {"status": 403, "response_class": "access_denied"},
        }
        (det / "cloud_exposure_findings.jsonl").write_text(json.dumps(row) + "\n")
        out = load_cloud_exposure_findings(td)
        assert out
        assert out[0]["priority_class"] in ("LEAD", "INTERESTING")


def test_atomic_write_not_empty_on_success():
    with tempfile.TemporaryDirectory() as td:
        det = Path(td) / "detection"
        det.mkdir()
        (Path(td) / "smart-fuzzing").mkdir()
        # minimal so builder runs
        import subprocess
        subprocess.check_call(
            ["python3", "pipeline/detection/hunter_queue_builder.py", "--results-dir", td, "--target", "t.com"],
            cwd=str(Path(__file__).resolve().parents[1]),
        )
        hq = det / "hunter_queue.md"
        assert hq.is_file()
        assert hq.stat().st_size > 0
