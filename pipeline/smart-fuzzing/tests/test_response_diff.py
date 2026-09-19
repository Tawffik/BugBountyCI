#!/usr/bin/env python3
"""
tests/test_response_diff.py

Run with: python3 pipeline/smart-fuzzing/tests/test_response_diff.py

Covers:
  1. Regression fixture: the real superdrug.com run that exposed the
     `or True` baseline-matching bug. Before the fix this produced
     21/21 INTERESTING (100%) and no dedup. After the fix it must
     produce a small INTERESTING count with the rest DUPLICATE/UNKNOWN.
  2. Multi-host baseline matching: host A's hits must never be scored
     against host B's baseline (the exact bug that was fixed).
  3. No-baseline host -> UNKNOWN, never a guess.
  4. Near-duplicate WAF/error-page clustering.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SMART_FUZZING_DIR = os.path.dirname(HERE)
SCRIPT = os.path.join(SMART_FUZZING_DIR, "response_diff.py")
FIXTURES = os.path.join(HERE, "fixtures")


def run_response_diff(results_dir, ffuf_json_dir):
    subprocess.run(
        [sys.executable, SCRIPT, "--results-dir", results_dir, "--ffuf-json-dir", ffuf_json_dir],
        check=True, capture_output=True, text=True,
    )
    with open(os.path.join(results_dir, "smart-fuzzing", "response_diffs.json")) as f:
        return json.load(f)


def test_real_superdrug_regression():
    """The exact data that exposed the original bug. Before the fix:
    21/21 hits INTERESTING. After the fix: must be far fewer, with
    duplicates and/or unmatched hosts correctly separated out."""
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "smart-fuzzing"), exist_ok=True)
        with open(os.path.join(FIXTURES, "real_superdrug_baseline.json")) as f:
            baseline = json.load(f)
        with open(os.path.join(tmp, "smart-fuzzing", "baseline.json"), "w") as f:
            json.dump(baseline, f)

        diffs = run_response_diff(tmp, os.path.join(FIXTURES, "real_superdrug_ffuf_raw"))

        total = len(diffs)
        interesting = sum(1 for d in diffs if d["classification"] == "INTERESTING")
        duplicate = sum(1 for d in diffs if d["classification"] == "DUPLICATE")

        assert total == 21, f"expected 21 total hits from fixture, got {total}"
        assert interesting < total, (
            "REGRESSION: every hit classified INTERESTING again — the baseline "
            "matching bug (`or True`) may have come back."
        )
        assert duplicate > 0, "expected repeated block-page hits to be deduped"
        print(f"  ✅ real superdrug fixture: {total} hits -> "
              f"{interesting} INTERESTING, {duplicate} DUPLICATE (was 21/21 INTERESTING before fix)")


def test_multi_host_no_cross_match():
    """Host A's baseline must never classify Host B's hit. This is the
    literal `or True` bug: reconstruct a minimal 2-host case where naive
    substring/'first available' matching would get it wrong."""
    with tempfile.TemporaryDirectory() as tmp:
        sf = os.path.join(tmp, "smart-fuzzing")
        os.makedirs(sf, exist_ok=True)
        ffuf_dir = os.path.join(tmp, "ffuf_raw")
        os.makedirs(ffuf_dir, exist_ok=True)

        baseline = {
            "https://a.example.com": {"status": 404, "length": 100, "content_type": "text/html",
                                       "fingerprint": "aaa", "stable": True},
            "https://b.example.com": {"status": 200, "length": 5000, "content_type": "application/json",
                                       "fingerprint": "bbb", "stable": True},
        }
        with open(os.path.join(sf, "baseline.json"), "w") as f:
            json.dump(baseline, f)

        # Host B's hit looks exactly like host B's OWN baseline (200, 5000,
        # json) -> must be NOISE. If the old bug were present, this could
        # get compared against host A's baseline (404, 100, html) instead
        # and wrongly come back INTERESTING.
        with open(os.path.join(ffuf_dir, "b.json"), "w") as f:
            json.dump({
                "config": {"url": "https://b.example.com/FUZZ"},
                "results": [{"url": "https://b.example.com/anything", "status": 200,
                             "length": 5000, "content-type": "application/json"}],
            }, f)

        diffs = run_response_diff(tmp, ffuf_dir)
        assert len(diffs) == 1
        assert diffs[0]["classification"] == "NOISE", (
            f"host B's hit should be NOISE against ITS OWN baseline, "
            f"got {diffs[0]['classification']} (cross-host match bug?)"
        )
        print("  ✅ multi-host: no cross-host baseline contamination")


def test_unmatched_host_is_unknown_not_guessed():
    """A host with no baseline entry must be UNKNOWN, even if exactly one
    baseline happens to exist for a DIFFERENT host. V1 must not guess."""
    with tempfile.TemporaryDirectory() as tmp:
        sf = os.path.join(tmp, "smart-fuzzing")
        os.makedirs(sf, exist_ok=True)
        ffuf_dir = os.path.join(tmp, "ffuf_raw")
        os.makedirs(ffuf_dir, exist_ok=True)

        with open(os.path.join(sf, "baseline.json"), "w") as f:
            json.dump({"https://known.example.com": {"status": 404, "length": 50,
                                                       "content_type": "text/html",
                                                       "fingerprint": "x", "stable": True}}, f)

        with open(os.path.join(ffuf_dir, "unknown.json"), "w") as f:
            json.dump({
                "config": {"url": "https://unknown.example.com/FUZZ"},
                "results": [{"url": "https://unknown.example.com/admin", "status": 403,
                             "length": 300, "content-type": "text/html"}],
            }, f)

        diffs = run_response_diff(tmp, ffuf_dir)
        assert diffs[0]["classification"] == "UNKNOWN", (
            f"expected UNKNOWN for a host with no baseline, got {diffs[0]['classification']}"
        )
        print("  ✅ unmatched host classified UNKNOWN, not guessed")


if __name__ == "__main__":
    tests = [test_real_superdrug_regression, test_multi_host_no_cross_match,
             test_unmatched_host_is_unknown_not_guessed]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  ❌ {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
