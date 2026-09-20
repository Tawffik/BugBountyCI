#!/usr/bin/env python3
"""
pipeline/detection/tests/test_hunter_queue_builder.py
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, REPO_ROOT)

from pipeline.detection.hunter_queue_builder import (
    load_detection_evidence, load_idor_findings, load_smart_fuzzing_interesting,
    render_markdown, PRIORITY_ORDER,
)


def _rd():
    return tempfile.mkdtemp()


def test_empty_run_produces_clean_no_signals_message():
    tmp = _rd()
    try:
        md = render_markdown([], "example.com")
        assert "No signals reached" in md
        assert "example.com" in md
        print("  ✅ empty run produces a clean 'no signals' message, not an empty/broken file")
    finally:
        shutil.rmtree(tmp)


def test_priority_ordering():
    entries = [
        {"priority_class": "INTERESTING", "engine": "x", "target": "a", "reason": "r", "stable": None},
        {"priority_class": "HIGH_SIGNAL", "engine": "x", "target": "b", "reason": "r", "stable": True},
        {"priority_class": "LEAD", "engine": "x", "target": "c", "reason": "r", "stable": None},
        {"priority_class": "IDOR-CANDIDATE", "engine": "x", "target": "d", "reason": "r", "stable": None},
    ]
    md = render_markdown(entries, "x")
    # HIGH_SIGNAL must appear before IDOR-CANDIDATE, before LEAD, before INTERESTING
    pos_high = md.index("[HIGH_SIGNAL]")
    pos_idor = md.index("[IDOR-CANDIDATE]")
    pos_lead = md.index("[LEAD]")
    pos_interesting = md.index("[INTERESTING]")
    assert pos_high < pos_idor < pos_lead < pos_interesting
    print("  ✅ priority ordering correct: HIGH_SIGNAL > IDOR-CANDIDATE > LEAD > INTERESTING")


def test_noise_and_duplicate_never_reach_the_queue():
    tmp = _rd()
    try:
        det_dir = os.path.join(tmp, "detection")
        os.makedirs(det_dir)
        with open(os.path.join(det_dir, "engine_results.json"), "w") as f:
            json.dump([{
                "engine": "access-control-v1", "ran": True, "error": None, "candidates_generated": 3,
                "evidence": [
                    {"candidate": {"target": "https://x.com/a"}, "classification": "NOISE", "reason": "r", "stable": None},
                    {"candidate": {"target": "https://x.com/b"}, "classification": "DUPLICATE", "reason": "r", "stable": None},
                    {"candidate": {"target": "https://x.com/c"}, "classification": "LEAD", "reason": "real signal", "stable": None},
                ],
            }], f)
        entries = load_detection_evidence(tmp)
        assert len(entries) == 1
        assert entries[0]["target"] == "https://x.com/c"
        print("  ✅ NOISE and DUPLICATE excluded from the hunter queue, only LEAD kept")
    finally:
        shutil.rmtree(tmp)


def test_idor_findings_parsed_correctly():
    tmp = _rd()
    try:
        ai_dir = os.path.join(tmp, "ai_agent")
        os.makedirs(ai_dir)
        with open(os.path.join(ai_dir, "idor_findings.txt"), "w") as f:
            f.write("[IDOR-CANDIDATE] https://x.com/invoice/1042 | Status:200 | Body:5000 chars | "
                    "authenticated request - needs manual verification\n")
        entries = load_idor_findings(tmp)
        assert len(entries) == 1
        assert entries[0]["priority_class"] == "IDOR-CANDIDATE"
        assert entries[0]["target"] == "https://x.com/invoice/1042"
        print("  ✅ IDOR-CANDIDATE line parsed correctly from ai_agent/idor_findings.txt")
    finally:
        shutil.rmtree(tmp)


def test_no_idor_findings_placeholder_produces_zero_entries():
    tmp = _rd()
    try:
        ai_dir = os.path.join(tmp, "ai_agent")
        os.makedirs(ai_dir)
        with open(os.path.join(ai_dir, "idor_findings.txt"), "w") as f:
            f.write("No IDOR findings\n")
        entries = load_idor_findings(tmp)
        assert entries == []
        print("  ✅ 'No IDOR findings' placeholder line correctly produces zero entries, not a fake one")
    finally:
        shutil.rmtree(tmp)


def test_missing_files_all_degrade_gracefully():
    tmp = _rd()
    try:
        assert load_detection_evidence(tmp) == []
        assert load_idor_findings(tmp) == []
        assert load_smart_fuzzing_interesting(tmp) == []
        print("  ✅ all three loaders degrade to empty list when their source file doesn't exist")
    finally:
        shutil.rmtree(tmp)


def test_against_real_run_data():
    """Uses the actual response_diffs.json/interesting.txt fixture from
    the real superdrug.com run already committed for response_diff.py's
    own tests - not synthetic-only data."""
    fixtures = os.path.join(REPO_ROOT, "pipeline", "smart-fuzzing", "tests", "fixtures")
    real_ffuf_dir = os.path.join(fixtures, "real_superdrug_ffuf_raw")
    if not os.path.isdir(real_ffuf_dir):
        print("  ⚠️ skipped: real superdrug fixture not found")
        return

    import subprocess
    tmp = _rd()
    try:
        sf_dir = os.path.join(tmp, "smart-fuzzing")
        os.makedirs(sf_dir)
        shutil.copy(os.path.join(fixtures, "real_superdrug_baseline.json"), os.path.join(sf_dir, "baseline.json"))
        subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "pipeline", "smart-fuzzing", "response_diff.py"),
             "--results-dir", tmp, "--ffuf-json-dir", real_ffuf_dir],
            check=True, capture_output=True, text=True,
        )
        entries = load_smart_fuzzing_interesting(tmp)
        assert len(entries) > 0, "expected at least one INTERESTING entry from the real fixture"
        md = render_markdown(entries, "superdrug.com")
        assert "[INTERESTING]" in md
        print(f"  ✅ real superdrug fixture produces {len(entries)} INTERESTING entr{'y' if len(entries)==1 else 'ies'} "
              f"in the merged hunter queue")
    finally:
        shutil.rmtree(tmp)


if __name__ == "__main__":
    tests = [
        test_empty_run_produces_clean_no_signals_message,
        test_priority_ordering,
        test_noise_and_duplicate_never_reach_the_queue,
        test_idor_findings_parsed_correctly,
        test_no_idor_findings_placeholder_produces_zero_entries,
        test_missing_files_all_degrade_gracefully,
        test_against_real_run_data,
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
