#!/usr/bin/env python3
"""
pipeline/detection/tests/test_metrics_builder.py
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, REPO_ROOT)

from pipeline.detection.metrics_builder import (
    build_metrics, detect_near_duplicate_clusters, _signal_precision,
)


def _rd_with_engine_results(engine_results):
    tmp = tempfile.mkdtemp()
    det_dir = os.path.join(tmp, "detection")
    os.makedirs(det_dir)
    with open(os.path.join(det_dir, "engine_results.json"), "w") as f:
        json.dump(engine_results, f)
    return tmp


def test_signal_precision_counts_interesting_as_signal():
    """Real bug found on the first test against okx.com data: response_diff.py
    uses its own legacy 'INTERESTING' label (predates the Detection
    Engine Framework's enum), which wasn't being counted as signal at
    all, reporting 0.0 precision on a run with 6 genuine hits."""
    counts = {"NOISE": 40, "DUPLICATE": 13, "INTERESTING": 6}
    precision = _signal_precision(counts)
    assert precision == round(6 / 59, 3)
    print(f"  ✅ INTERESTING correctly counted as signal (precision={precision}, was reporting 0.0)")


def test_signal_precision_zero_evidence_is_zero_not_crash():
    assert _signal_precision({}) == 0.0
    print("  ✅ zero evidence -> 0.0 precision, no division-by-zero crash")


def test_cluster_detection_on_real_okx_pattern():
    """The exact real pattern that motivated this file: 6 INTERESTING
    hits, 3 on each of 2 hosts, with near-identical byte-diffs within
    each host - reconstructed from the actual okx.com hunter_queue.md
    data (byte diffs: 50326/50309/50300 on app.okx.com,
    61332/61315/61306 on www.okx.com)."""
    evidence = [
        {"classification": "INTERESTING", "candidate": {"target": "https://app.okx.com/.admin/"},
         "reason": "status 301 != baseline 404; length differs by 50326 bytes from baseline"},
        {"classification": "INTERESTING", "candidate": {"target": "https://app.okx.com/Database_Administration/"},
         "reason": "status 301 != baseline 404; length differs by 50309 bytes from baseline"},
        {"classification": "INTERESTING", "candidate": {"target": "https://app.okx.com/account"},
         "reason": "status 302 != baseline 404; length differs by 50300 bytes from baseline"},
        {"classification": "INTERESTING", "candidate": {"target": "https://www.okx.com/.admin/"},
         "reason": "status 301 != baseline 404; length differs by 61332 bytes from baseline"},
        {"classification": "INTERESTING", "candidate": {"target": "https://www.okx.com/Database_Administration/"},
         "reason": "status 301 != baseline 404; length differs by 61315 bytes from baseline"},
        {"classification": "INTERESTING", "candidate": {"target": "https://www.okx.com/account"},
         "reason": "status 302 != baseline 404; length differs by 61306 bytes from baseline"},
    ]
    clusters = detect_near_duplicate_clusters(evidence)
    assert len(clusters) == 2
    hosts = {c["host"] for c in clusters}
    assert hosts == {"app.okx.com", "www.okx.com"}
    assert all(c["size"] == 3 for c in clusters)
    print(f"  ✅ real okx.com pattern correctly clustered: {len(clusters)} clusters "
          f"(app.okx.com x3, www.okx.com x3) - matches the manual chart analysis exactly")


def test_genuinely_distinct_signals_are_not_clustered():
    """Two INTERESTING hits with very different byte diffs, on
    different hosts, must NOT be merged into a false cluster."""
    evidence = [
        {"classification": "INTERESTING", "candidate": {"target": "https://a.example.com/x"},
         "reason": "length differs by 500 bytes from baseline"},
        {"classification": "INTERESTING", "candidate": {"target": "https://b.example.com/y"},
         "reason": "length differs by 90000 bytes from baseline"},
    ]
    clusters = detect_near_duplicate_clusters(evidence)
    assert clusters == []
    print("  ✅ genuinely distinct single signals on different hosts/magnitudes not falsely clustered")


def test_build_metrics_end_to_end_with_mixed_engines():
    engine_results = [
        {"engine": "access-control-v1", "ran": True, "error": None, "candidates_generated": 5,
         "duration_s": 1.2, "evidence": [
            {"classification": "NOISE"}, {"classification": "HIGH_SIGNAL"}]},
        {"engine": "open-redirect-v1", "ran": True, "error": None, "candidates_generated": 10,
         "duration_s": 0.5, "evidence": [{"classification": "NOISE"}] * 3},
    ]
    tmp = _rd_with_engine_results(engine_results)
    try:
        metrics = build_metrics(tmp)
        assert metrics["engines"]["access-control-v1"]["signal_precision"] == 0.5
        assert metrics["engines"]["open-redirect-v1"]["signal_precision"] == 0.0
        assert metrics["overall"]["total_candidates"] == 15
        assert metrics["overall"]["total_evidence"] == 5
        assert metrics["overall"]["raw_signal_count"] == 1
        print("  ✅ end-to-end metrics build across 2 real-shaped engines, per-engine and overall correct")
    finally:
        shutil.rmtree(tmp)


def test_missing_files_degrade_gracefully():
    with tempfile.TemporaryDirectory() as tmp:
        metrics = build_metrics(tmp)
        assert metrics["overall"]["total_candidates"] == 0
        assert metrics["overall"]["signal_precision"] == 0.0
        print("  ✅ missing engine_results.json/response_diffs.json -> empty metrics, no crash")


if __name__ == "__main__":
    tests = [
        test_signal_precision_counts_interesting_as_signal,
        test_signal_precision_zero_evidence_is_zero_not_crash,
        test_cluster_detection_on_real_okx_pattern,
        test_genuinely_distinct_signals_are_not_clustered,
        test_build_metrics_end_to_end_with_mixed_engines,
        test_missing_files_degrade_gracefully,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  ❌ {t.__name__}: {e}")
        except Exception as e:
            failed += 1
            print(f"  ❌ {t.__name__}: unexpected {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
