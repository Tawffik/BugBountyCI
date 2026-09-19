#!/usr/bin/env python3
"""
pipeline/detection/tests/test_framework.py

Proves the Detection Engine Framework works end-to-end using a toy
engine, BEFORE any real vulnerability engine gets built on top of it.
Run with: python3 pipeline/detection/tests/test_framework.py
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, REPO_ROOT)

from pipeline.detection.engine import (
    Candidate, Evidence, DetectionEngine, run_engine, run_engines, VALID_CLASSIFICATIONS,
)
from pipeline.detection.tests.toy_engine import ToyOpenRedirectEngine


def test_prerequisites_gate_skips_engine():
    engine = ToyOpenRedirectEngine()
    result = run_engine(engine, target_profile={"hosts": []}, vocabulary={"redirect": {"sources": ["url"]}})
    assert result.ran is True
    assert result.candidates_generated == 0
    assert "prerequisites" in (result.error or "")
    print("  ✅ engine with unmet prerequisites is skipped, not crashed")


def test_no_relevant_vocabulary_produces_zero_candidates():
    """Evidence-based candidate generation: no redirect-like word in
    vocabulary means zero candidates, not a guess."""
    engine = ToyOpenRedirectEngine()
    profile = {"hosts": ["https://example.com"]}
    result = run_engine(engine, profile, vocabulary={"invoice": {"sources": ["js"]}})
    assert result.candidates_generated == 0
    print("  ✅ no supporting vocabulary -> zero candidates (evidence-based, not guessed)")


def test_end_to_end_detects_and_classifies():
    """Full path: candidates generated from vocabulary, detect() finds a
    signal via an injected fake prober, classification comes back valid."""
    def fake_prober(url):
        if "evil.example" in url:
            return {"status": 302, "location": "https://evil.example/"}
        return None

    engine = ToyOpenRedirectEngine(prober=fake_prober)
    profile = {"hosts": ["https://example.com"]}
    vocabulary = {"redirect": {"sources": ["js", "url"]}}

    result = run_engine(engine, profile, vocabulary)
    assert result.ran is True
    assert result.candidates_generated == 1
    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert ev.classification in VALID_CLASSIFICATIONS
    assert ev.classification == "LEAD"
    assert "evil.example" in ev.candidate.target
    assert ev.candidate.evidence_sources == ["js", "url"]
    print(f"  ✅ end-to-end: candidate generated, detected, classified as {ev.classification}")


def test_invalid_classification_is_rejected():
    """The Golden Rule enforcement: an engine cannot invent its own label
    like 'VULNERABILITY_FOUND'."""
    c = Candidate(target="https://example.com/x", engine="toy")
    try:
        Evidence(candidate=c, classification="VULNERABILITY_FOUND", reason="nope")
        raised = False
    except ValueError:
        raised = True
    assert raised, "Evidence must reject classifications outside VALID_CLASSIFICATIONS"
    print("  ✅ inventing a non-standard classification (e.g. 'VULNERABILITY_FOUND') is rejected")


def test_broken_engine_does_not_crash_the_batch():
    """A real engine that raises inside generate_candidates must not stop
    other engines from running — mirrors the pipeline's continue-on-error
    philosophy everywhere else."""
    class BrokenEngine(DetectionEngine):
        name = "broken-engine"
        def prerequisites(self, target_profile):
            return True
        def generate_candidates(self, target_profile, vocabulary):
            raise RuntimeError("intentional failure for this test")

    good_engine = ToyOpenRedirectEngine(prober=lambda u: {"status": 302, "location": "https://evil.example/"})
    profile = {"hosts": ["https://example.com"]}
    vocabulary = {"redirect": {"sources": ["js"]}}

    with tempfile.TemporaryDirectory() as tmp:
        results = run_engines([BrokenEngine(), good_engine], profile, vocabulary, results_dir=tmp)
        by_name = {r.engine: r for r in results}
        assert by_name["broken-engine"].ran is False
        assert by_name["broken-engine"].error is not None
        assert by_name["toy-open-redirect"].ran is True
        assert len(by_name["toy-open-redirect"].evidence) == 1

        out_path = os.path.join(tmp, "detection", "engine_results.json")
        assert os.path.isfile(out_path)
        with open(out_path) as f:
            written = json.load(f)
        assert len(written) == 2
        print("  ✅ one broken engine doesn't stop the other, both recorded in engine_results.json")


def test_candidate_cap_bounds_output():
    """max_candidates must actually cap, so a future engine can't explode
    a run the way vocabulary.py once did before its own cap was added."""
    class ManyCandidatesEngine(DetectionEngine):
        name = "many-candidates"
        def generate_candidates(self, target_profile, vocabulary):
            return [Candidate(target=f"https://example.com/{i}", engine=self.name) for i in range(10000)]
        def detect(self, candidate):
            return None

    result = run_engine(ManyCandidatesEngine(), {"hosts": ["x"]}, {}, max_candidates=50)
    assert result.candidates_generated == 50, f"expected cap at 50, got {result.candidates_generated}"
    print("  ✅ max_candidates cap enforced (50 out of 10000 generated)")


def test_multiple_run_engines_calls_merge_not_overwrite():
    """The real bug this test catches: run_access_control.py and
    run_open_redirect.py each call run_engines() independently, in
    sequence, within the same workflow run. Before the fix, the second
    call's plain 'w' file write silently discarded the first call's
    results. Found in a pre-run code review, not from lost real data."""
    engine_a = ToyOpenRedirectEngine(prober=lambda u: {"status": 302, "location": "https://evil.example/"})
    engine_a.name = "engine-a"
    engine_b = ToyOpenRedirectEngine(prober=lambda u: {"status": 302, "location": "https://evil.example/"})
    engine_b.name = "engine-b"

    profile = {"hosts": ["https://example.com"]}
    vocabulary = {"redirect": {"sources": ["js"]}}

    with tempfile.TemporaryDirectory() as tmp:
        run_engines([engine_a], profile, vocabulary, results_dir=tmp)
        run_engines([engine_b], profile, vocabulary, results_dir=tmp)  # separate call, like a second CLI script

        with open(os.path.join(tmp, "detection", "engine_results.json")) as f:
            written = json.load(f)
        names = {r["engine"] for r in written}
        assert names == {"engine-a", "engine-b"}, (
            f"expected both engines' results preserved across separate run_engines() calls, "
            f"got only: {names} (the second call overwrote the first)"
        )
        print("  ✅ two separate run_engines() calls merge results instead of the second overwriting the first")


def test_rerunning_same_engine_replaces_only_its_own_entry():
    """Re-running the SAME engine (e.g. a retried step) should replace
    just that engine's old entry, not duplicate it or wipe others."""
    engine_a = ToyOpenRedirectEngine(prober=lambda u: {"status": 302, "location": "https://evil.example/"})
    engine_a.name = "engine-a"
    engine_b = ToyOpenRedirectEngine(prober=lambda u: {"status": 302, "location": "https://evil.example/"})
    engine_b.name = "engine-b"
    profile = {"hosts": ["https://example.com"]}
    vocabulary = {"redirect": {"sources": ["js"]}}

    with tempfile.TemporaryDirectory() as tmp:
        run_engines([engine_a], profile, vocabulary, results_dir=tmp)
        run_engines([engine_b], profile, vocabulary, results_dir=tmp)
        run_engines([engine_a], profile, vocabulary, results_dir=tmp)  # re-run engine-a

        with open(os.path.join(tmp, "detection", "engine_results.json")) as f:
            written = json.load(f)
        names = [r["engine"] for r in written]
        assert names.count("engine-a") == 1, f"engine-a should appear exactly once, appeared {names.count('engine-a')} times"
        assert "engine-b" in names
        print("  ✅ re-running the same engine replaces its own entry only, doesn't duplicate or wipe others")


if __name__ == "__main__":
    tests = [
        test_prerequisites_gate_skips_engine,
        test_no_relevant_vocabulary_produces_zero_candidates,
        test_end_to_end_detects_and_classifies,
        test_invalid_classification_is_rejected,
        test_broken_engine_does_not_crash_the_batch,
        test_candidate_cap_bounds_output,
        test_multiple_run_engines_calls_merge_not_overwrite,
        test_rerunning_same_engine_replaces_only_its_own_entry,
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
