#!/usr/bin/env python3
"""
pipeline/detection/tests/test_access_control_engine.py

Tests the first real engine (AccessControlEngine) end-to-end, including
against the same real superdrug.com fixture data used to fix
response_diff.py's baseline bug — this engine consumes THAT file's
output, so testing against the real thing (not just synthetic data) is
what actually proves the reuse works.
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, REPO_ROOT)

from pipeline.detection.engine import run_engine
from pipeline.detection.access_control_engine import AccessControlEngine, _mutate_url, PATH_MUTATIONS

SMART_FUZZING_FIXTURES = os.path.join(
    REPO_ROOT, "pipeline", "smart-fuzzing", "tests", "fixtures"
)


def _make_results_dir_with_diffs(diffs):
    tmp = tempfile.mkdtemp()
    sf_dir = os.path.join(tmp, "smart-fuzzing")
    os.makedirs(sf_dir, exist_ok=True)
    with open(os.path.join(sf_dir, "response_diffs.json"), "w") as f:
        json.dump(diffs, f)
    return tmp


def test_mutations_produce_distinct_urls():
    url = "https://example.com/admin"
    mutated = {_mutate_url(url, m) for m in PATH_MUTATIONS}
    mutated.discard(None)
    assert len(mutated) == len(PATH_MUTATIONS), "each mutator should produce a distinct URL"
    assert all(m != url for m in mutated)
    print(f"  ✅ {len(mutated)} distinct safe path mutations generated for one endpoint")


def test_no_prerequisites_without_response_diffs():
    with tempfile.TemporaryDirectory() as tmp:
        engine = AccessControlEngine(results_dir=tmp)
        result = run_engine(engine, target_profile={}, vocabulary={})
        assert result.ran is True
        assert "prerequisites" in (result.error or "")
        print("  ✅ engine correctly skips when smart-fuzzing hasn't run yet")


def test_duplicate_hits_are_not_turned_into_candidates():
    diffs = [
        {"url": "https://a.example.com/_admin", "status": 403, "length": 381,
         "content_type": "text/html", "classification": "DUPLICATE"},
        {"url": "https://a.example.com/_admincp", "status": 403, "length": 383,
         "content_type": "text/html", "classification": "DUPLICATE"},
    ]
    tmp = _make_results_dir_with_diffs(diffs)
    try:
        engine = AccessControlEngine(results_dir=tmp)
        result = run_engine(engine, {}, {})
        assert result.candidates_generated == 0, "DUPLICATE hits must not spawn access-control candidates"
        print("  ✅ DUPLICATE-classified hits produce zero access-control candidates (no re-multiplying noise)")
    finally:
        shutil.rmtree(tmp)


def test_detect_alone_never_exceeds_lead():
    """Golden Rule enforcement at the detect() level specifically: a
    single response observation, with NO replay involved at all, must
    never come back as anything stronger than LEAD. (verify() — tested
    separately below — is what's allowed to promote to HIGH_SIGNAL, and
    only with real replay evidence.)"""
    diffs = [{"url": "https://example.com/admin", "status": 403, "length": 400,
              "content_type": "text/html", "classification": "INTERESTING"}]
    tmp = _make_results_dir_with_diffs(diffs)
    try:
        def prober(url):
            return {"status": 200, "length": 50000, "content_type": "application/json"}

        engine = AccessControlEngine(results_dir=tmp, prober=prober)
        candidates = engine.generate_candidates({}, {})
        assert candidates, "expected at least one candidate from the fixture"
        ev = engine.detect(candidates[0])  # detect() only, verify() deliberately not called
        assert ev is not None
        assert ev.classification in ("NOISE", "LEAD"), (
            f"detect() alone must never exceed LEAD, got {ev.classification}"
        )
        print(f"  ✅ detect() alone (no replay) capped at {ev.classification}, never HIGH_SIGNAL")
    finally:
        shutil.rmtree(tmp)


def test_stable_endpoint_specific_replay_promotes_to_high_signal():
    diffs = [{"url": "https://example.com/admin", "status": 403, "length": 400,
              "content_type": "text/html", "classification": "INTERESTING"}]
    tmp = _make_results_dir_with_diffs(diffs)
    try:
        # Same response every single call (detect + 2 replays) = stable,
        # and dramatically different from the 403 baseline = endpoint-specific.
        def prober(url):
            return {"status": 200, "length": 50000, "content_type": "application/json"}

        engine = AccessControlEngine(results_dir=tmp, prober=prober)
        result = run_engine(engine, {}, {})
        high_signal = [e for e in result.evidence if e.classification == "HIGH_SIGNAL"]
        assert high_signal, f"expected at least one HIGH_SIGNAL, got: {[e.classification for e in result.evidence]}"
        assert high_signal[0].stable is True
        print(f"  ✅ stable + endpoint-specific replay promoted to HIGH_SIGNAL "
              f"({len(high_signal)} of {len(result.evidence)} evidence items)")
    finally:
        shutil.rmtree(tmp)


def test_unstable_replay_is_not_promoted():
    diffs = [{"url": "https://example.com/admin", "status": 403, "length": 400,
              "content_type": "text/html", "classification": "INTERESTING"}]
    tmp = _make_results_dir_with_diffs(diffs)
    try:
        call_count = {"n": 0}
        def flaky_prober(url):
            call_count["n"] += 1
            # First call (detect): looks interesting. Replays: flip-flops.
            if call_count["n"] % 2 == 0:
                return {"status": 200, "length": 50000, "content_type": "application/json"}
            return {"status": 503, "length": 10, "content_type": "text/plain"}

        engine = AccessControlEngine(results_dir=tmp, prober=flaky_prober)
        result = run_engine(engine, {}, {})
        assert not any(e.classification == "HIGH_SIGNAL" for e in result.evidence), (
            "unstable replay must never be promoted to HIGH_SIGNAL"
        )
        print("  ✅ unstable (flip-flopping) replay correctly withheld from HIGH_SIGNAL")
    finally:
        shutil.rmtree(tmp)


def test_against_real_superdrug_fixture():
    """The real fixture data used to fix response_diff.py's baseline bug.
    Confirms the two modules actually chain together correctly on real
    data, not just synthetic examples."""
    real_baseline_path = os.path.join(SMART_FUZZING_FIXTURES, "real_superdrug_baseline.json")
    real_ffuf_dir = os.path.join(SMART_FUZZING_FIXTURES, "real_superdrug_ffuf_raw")
    if not os.path.isdir(real_ffuf_dir):
        print("  ⚠️ skipped: real superdrug fixture not found (expected if run outside this repo)")
        return

    # Reuse response_diff.py itself to produce real response_diffs.json,
    # exactly like the actual pipeline would - not hand-written test data.
    import subprocess
    tmp = tempfile.mkdtemp()
    try:
        sf_dir = os.path.join(tmp, "smart-fuzzing")
        os.makedirs(sf_dir, exist_ok=True)
        shutil.copy(real_baseline_path, os.path.join(sf_dir, "baseline.json"))
        subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "pipeline", "smart-fuzzing", "response_diff.py"),
             "--results-dir", tmp, "--ffuf-json-dir", real_ffuf_dir],
            check=True, capture_output=True, text=True,
        )

        # No prober configured (no live network in this test environment) -
        # this still proves candidate generation reads the real file correctly.
        engine = AccessControlEngine(results_dir=tmp)
        result = run_engine(engine, {}, {})
        assert result.ran is True
        assert result.candidates_generated > 0, "expected real 403 hits from the fixture to produce candidates"
        print(f"  ✅ real superdrug fixture: {result.candidates_generated} access-control "
              f"candidates generated from real 403 hits (0 evidence since no live prober configured, as expected)")
    finally:
        shutil.rmtree(tmp)


if __name__ == "__main__":
    tests = [
        test_mutations_produce_distinct_urls,
        test_no_prerequisites_without_response_diffs,
        test_duplicate_hits_are_not_turned_into_candidates,
        test_detect_alone_never_exceeds_lead,
        test_stable_endpoint_specific_replay_promotes_to_high_signal,
        test_unstable_replay_is_not_promoted,
        test_against_real_superdrug_fixture,
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
