#!/usr/bin/env python3
"""
pipeline/detection/tests/test_open_redirect_engine.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, REPO_ROOT)

from pipeline.detection.engine import run_engine
from pipeline.detection.open_redirect_engine import OpenRedirectEngine, CANARY_HOST


def test_no_evidence_no_candidates():
    """Core rule check: no redirect-like word in vocabulary -> zero
    candidates. This is not a guess-based fuzzer."""
    engine = OpenRedirectEngine()
    profile = {"hosts": ["https://example.com"]}
    result = run_engine(engine, profile, vocabulary={"invoice": {"sources": ["js"]}})
    assert result.candidates_generated == 0
    print("  ✅ no redirect-like vocabulary -> zero candidates")


def test_prerequisites_gate_on_hosts():
    engine = OpenRedirectEngine()
    result = run_engine(engine, {"hosts": []}, {"redirect": {"sources": ["url"]}})
    assert result.ran is True
    assert "prerequisites" in (result.error or "")
    print("  ✅ no hosts -> engine skipped cleanly")


def test_internal_relative_redirect_is_noise():
    def prober(url):
        return {"status": 302, "location": "/login"}
    engine = OpenRedirectEngine(prober=prober)
    profile = {"hosts": ["https://example.com"]}
    result = run_engine(engine, profile, {"redirect": {"sources": ["js"]}})
    assert len(result.evidence) == 1
    assert result.evidence[0].classification == "NOISE"
    print("  ✅ relative internal redirect (/login) correctly classified NOISE")


def test_same_host_redirect_is_noise():
    def prober(url):
        return {"status": 302, "location": "https://example.com/dashboard"}
    engine = OpenRedirectEngine(prober=prober)
    profile = {"hosts": ["https://example.com"]}
    result = run_engine(engine, profile, {"redirect": {"sources": ["js"]}})
    assert result.evidence[0].classification == "NOISE"
    assert "internal" in result.evidence[0].reason
    print("  ✅ same-host absolute redirect correctly classified NOISE (internal, not exploitable)")


def test_unrelated_external_redirect_is_noise_not_leaked_signal():
    """A redirect to SOME external host that is NOT our injected canary
    must not be treated as evidence of injection - it could be a
    legitimate third-party redirect (payment gateway, SSO, etc.)."""
    def prober(url):
        return {"status": 302, "location": "https://legitimate-payment-provider.com/checkout"}
    engine = OpenRedirectEngine(prober=prober)
    profile = {"hosts": ["https://example.com"]}
    result = run_engine(engine, profile, {"redirect": {"sources": ["js"]}})
    assert result.evidence[0].classification == "NOISE"
    print("  ✅ external redirect to an UNRELATED host (not our canary) correctly classified NOISE, "
          "not mistaken for injected redirect evidence")


def test_canary_redirect_single_observation_capped_at_lead():
    def prober(url):
        return {"status": 302, "location": f"https://{CANARY_HOST}/"}
    engine = OpenRedirectEngine(prober=prober)
    profile = {"hosts": ["https://example.com"]}
    candidates = engine.generate_candidates(profile, {"redirect": {"sources": ["js", "url"]}})
    assert candidates
    ev = engine.detect(candidates[0])  # detect() alone, no replay
    assert ev.classification == "LEAD", f"single observation must be capped at LEAD, got {ev.classification}"
    print("  ✅ detect() alone (canary matched, no replay) capped at LEAD")


def test_canary_redirect_stable_replay_promotes_to_high_signal():
    def prober(url):
        return {"status": 302, "location": f"https://{CANARY_HOST}/"}
    engine = OpenRedirectEngine(prober=prober)
    profile = {"hosts": ["https://example.com"]}
    result = run_engine(engine, profile, {"redirect": {"sources": ["js", "url"]}})
    assert any(e.classification == "HIGH_SIGNAL" for e in result.evidence)
    print("  ✅ stable replay to the canary host promotes to HIGH_SIGNAL")


def test_candidate_cap_enforced():
    """Same discipline as vocabulary.py's MAX_VOCAB_SIZE and
    AccessControlEngine's max_endpoints: no engine generates unbounded
    candidates, even with many hosts and many matching redirect words."""
    engine = OpenRedirectEngine(max_candidates=10)
    profile = {"hosts": [f"https://host{i}.example.com" for i in range(50)]}
    vocabulary = {w: {"sources": ["js"]} for w in
                  ["redirect", "url", "next", "return", "returnurl", "continue", "destination", "callback", "goto"]}
    candidates = engine.generate_candidates(profile, vocabulary)
    assert len(candidates) == 10, f"expected cap at 10, got {len(candidates)}"
    print(f"  ✅ candidate cap enforced (10 of {50*9} possible combinations)")


def test_no_network_prober_never_makes_live_calls_by_default():
    """An engine instantiated without an explicit prober must never
    silently attempt live traffic."""
    engine = OpenRedirectEngine()  # no prober passed
    profile = {"hosts": ["https://example.com"]}
    result = run_engine(engine, profile, {"redirect": {"sources": ["js"]}})
    assert result.candidates_generated > 0
    assert len(result.evidence) == 0, "default no-op prober must return None, producing zero evidence"
    print("  ✅ default (no prober configured) makes zero live requests")


if __name__ == "__main__":
    tests = [
        test_no_evidence_no_candidates,
        test_prerequisites_gate_on_hosts,
        test_internal_relative_redirect_is_noise,
        test_same_host_redirect_is_noise,
        test_unrelated_external_redirect_is_noise_not_leaked_signal,
        test_canary_redirect_single_observation_capped_at_lead,
        test_canary_redirect_stable_replay_promotes_to_high_signal,
        test_candidate_cap_enforced,
        test_no_network_prober_never_makes_live_calls_by_default,
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
