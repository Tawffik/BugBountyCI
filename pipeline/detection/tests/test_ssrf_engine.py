import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from pipeline.detection.ssrf_engine import SSRFEngine, INTERNAL_PAYLOADS, BASELINE_CANARY

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


class TestPrerequisites(unittest.TestCase):
    def test_no_parameter_map_skips_engine(self):
        eng = SSRFEngine(parameter_map={"endpoints": []})
        self.assertFalse(eng.prerequisites({}))

    def test_with_endpoints_runs(self):
        eng = SSRFEngine(parameter_map={"endpoints": [{"endpoint": "https://x.com/a", "parameters": []}]})
        self.assertTrue(eng.prerequisites({}))


class TestCandidateGeneration(unittest.TestCase):
    def setUp(self):
        self.parameter_map = {
            "endpoints": [
                {
                    "endpoint": "https://onlinepharmacy.superdrug.com/wp-json/oembed/1.0/embed",
                    "parameters": [{"name": "url", "sources": ["js/api_endpoints"]}],
                },
                {
                    # not SSRF-relevant — must be excluded, this engine
                    # must not test every parameter on every endpoint
                    "endpoint": "https://x.com/search",
                    "parameters": [{"name": "query", "sources": ["urls/params"]}],
                },
                {
                    "endpoint": "https://x.com/auth/logout/",
                    "parameters": [{"name": "redirect", "sources": ["urls/params"]}],
                },
            ]
        }

    def test_only_ssrf_relevant_params_become_candidates(self):
        eng = SSRFEngine(parameter_map=self.parameter_map)
        cands = eng.generate_candidates({}, {})
        params = {c.metadata["parameter"] for c in cands}
        self.assertIn("url", params)
        self.assertIn("redirect", params)
        self.assertNotIn("query", params)

    def test_real_wordpress_oembed_endpoint_surfaced(self):
        # Real find on superdrug.com's actual parameter_intelligence.json:
        # WordPress's built-in oEmbed proxy is a well-documented
        # real-world SSRF vector — this must not get filtered out.
        eng = SSRFEngine(parameter_map=self.parameter_map)
        cands = eng.generate_candidates({}, {})
        targets = [c.target for c in cands]
        self.assertTrue(any("oembed" in t for t in targets))

    def test_target_specific_vocabulary_cross_pollinates(self):
        # A word this target itself uses (not in the static HUNT list)
        # but containing a known-relevant root must still count —
        # same "target's own evidence" philosophy as pattern_predictor.py.
        pm = {"endpoints": [{"endpoint": "https://x.com/preview",
                              "parameters": [{"name": "avatar_source_link", "sources": ["js"]}]}]}
        eng = SSRFEngine(parameter_map=pm)
        cands = eng.generate_candidates({}, {"avatar_source_link": {"count": 1, "sources": ["js"]}})
        self.assertEqual(len(cands), 1)

    def test_candidate_cap_respected(self):
        many = {"endpoints": [
            {"endpoint": f"https://x.com/e{i}", "parameters": [{"name": "url", "sources": ["js"]}]}
            for i in range(200)
        ]}
        eng = SSRFEngine(parameter_map=many, max_candidates=10)
        cands = eng.generate_candidates({}, {})
        self.assertLessEqual(len(cands), 10)


class TestDetection(unittest.TestCase):
    def _candidate(self):
        eng = SSRFEngine(parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })
        return eng, eng.generate_candidates({}, {})[0]

    def test_no_prober_returns_none(self):
        eng, cand = self._candidate()
        self.assertIsNone(eng.detect(cand))

    def test_identical_responses_classified_noise(self):
        def prober(url):
            return {"status": 400, "body": "bad request", "elapsed_ms": 50}
        eng = SSRFEngine(prober=prober, parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })
        cand = eng.generate_candidates({}, {})[0]
        ev = eng.detect(cand)
        self.assertEqual(ev.classification, "NOISE")

    def test_reflected_metadata_body_is_lead(self):
        def prober(url):
            if "169.254.169.254" in url:
                return {"status": 200, "body": "ami-id\ninstance-id\nmeta-data listing", "elapsed_ms": 80}
            return {"status": 400, "body": "invalid url", "elapsed_ms": 50}
        eng = SSRFEngine(prober=prober, parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })
        cand = eng.generate_candidates({}, {})[0]
        ev = eng.detect(cand)
        self.assertEqual(ev.classification, "LEAD")
        self.assertEqual(ev.details["signal"], "reflected_body")

    def test_real_false_positive_regression_generic_metadata_word_not_lead(self):
        # Real bug caught on a live superdrug.com run: two candidates
        # were classified HIGH_SIGNAL purely because their response
        # body contained the ordinary word "metadata" somewhere (an
        # SEO <meta> tag, a JS bundle name, etc.) — completely
        # unrelated to SSRF. ai_agent/oob_findings.txt came back EMPTY
        # for both (zero real out-of-band callback), proving neither
        # server ever actually attempted the fetch. A single generic
        # substring match is not evidence; this must classify NOISE.
        def prober(url):
            return {
                "status": 200,
                "body": (
                    "<html><head><meta name='description' content='shop metadata'>"
                    "</head><body>page didn't load, invalid metadata in request</body></html>"
                ),
                "elapsed_ms": 60,
            }
        eng = SSRFEngine(prober=prober, parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })
        cand = eng.generate_candidates({}, {})[0]
        ev = eng.detect(cand)
        self.assertEqual(ev.classification, "NOISE")

    def test_payload_echoed_in_error_message_is_not_evidence(self):
        # Another real-shaped false positive: an app that just echoes
        # "invalid URL: <what you sent>" back verbatim in an error
        # message reflects the REQUEST, not fetched content — even if
        # the echoed payload string itself contains "169.254.169.254".
        def prober(url):
            payload = url.split("url=")[-1] if "url=" in url else ""
            from urllib.parse import unquote
            return {"status": 400, "body": f"Error: invalid URL supplied: {unquote(payload)}", "elapsed_ms": 40}
        eng = SSRFEngine(prober=prober, parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })
        cand = eng.generate_candidates({}, {})[0]
        ev = eng.detect(cand)
        self.assertNotEqual(ev.classification, "LEAD")

    def test_differential_status_is_lead_not_noise(self):
        def prober(url):
            if "127.0.0.1" in url:
                return {"status": 500, "body": "connection refused", "elapsed_ms": 40}
            return {"status": 400, "body": "invalid url", "elapsed_ms": 45}
        eng = SSRFEngine(prober=prober, parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })
        cand = eng.generate_candidates({}, {})[0]
        ev = eng.detect(cand)
        self.assertEqual(ev.classification, "LEAD")
        self.assertEqual(ev.details["signal"], "differential_response")

    def test_timing_delta_alone_is_lead(self):
        def prober(url):
            if "169.254.169.254" in url:
                return {"status": 400, "body": "invalid url", "elapsed_ms": 9000}  # hung trying to connect
            return {"status": 400, "body": "invalid url", "elapsed_ms": 60}
        eng = SSRFEngine(prober=prober, parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })
        cand = eng.generate_candidates({}, {})[0]
        ev = eng.detect(cand)
        self.assertEqual(ev.classification, "LEAD")


class TestVerify(unittest.TestCase):
    def test_stable_reflection_promotes_to_high_signal(self):
        def prober(url):
            if "169.254.169.254" in url:
                return {"status": 200, "body": "instance-id meta-data", "elapsed_ms": 80}
            return {"status": 400, "body": "invalid", "elapsed_ms": 40}
        eng = SSRFEngine(prober=prober, parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })
        cand = eng.generate_candidates({}, {})[0]
        ev = eng.verify(eng.detect(cand))
        self.assertEqual(ev.classification, "HIGH_SIGNAL")
        self.assertTrue(ev.stable)

    def test_unstable_replay_not_promoted(self):
        calls = {"n": 0}

        def prober(url):
            calls["n"] += 1
            if "169.254.169.254" in url and calls["n"] <= 2:
                return {"status": 200, "body": "meta-data", "elapsed_ms": 80}
            return {"status": 400, "body": "invalid", "elapsed_ms": 40}

        eng = SSRFEngine(prober=prober, parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })
        cand = eng.generate_candidates({}, {})[0]
        ev = eng.verify(eng.detect(cand))
        self.assertEqual(ev.classification, "LEAD")  # not promoted
        self.assertFalse(ev.stable)

    def test_noise_not_replayed(self):
        calls = {"n": 0}

        def prober(url):
            calls["n"] += 1
            return {"status": 400, "body": "same", "elapsed_ms": 40}

        eng = SSRFEngine(prober=prober, parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })
        cand = eng.generate_candidates({}, {})[0]
        ev = eng.detect(cand)
        calls_before_verify = calls["n"]
        eng.verify(ev)
        self.assertEqual(calls["n"], calls_before_verify)  # verify() skipped NOISE, no extra requests


class TestAdapterIsDocumentedNoOp(unittest.TestCase):
    def test_adapter_passes_evidence_through_unchanged(self):
        eng, cand = SSRFEngine(parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        }), None
        eng2 = SSRFEngine(parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })
        cand = eng2.generate_candidates({}, {})[0]
        from pipeline.detection.engine import Evidence
        ev = Evidence(candidate=cand, classification="LEAD", reason="test")
        out = eng2.adapter(cand, ev)
        self.assertIs(out, ev)


class TestAdapterWithoutOOBSession(unittest.TestCase):
    """When oob_domain is empty (no OOB session this run — public
    interactsh servers unreachable, matching the workflow's own
    documented fallback), adapter() must be a pure no-op, not crash."""

    def test_no_oob_domain_leaves_lead_unescalated(self):
        eng2 = SSRFEngine(parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        })  # oob_domain defaults to ""
        cand = eng2.generate_candidates({}, {})[0]
        from pipeline.detection.engine import Evidence
        ev = Evidence(candidate=cand, classification="LEAD", reason="test")
        out = eng2.adapter(cand, ev)
        self.assertIs(out, ev)
        self.assertNotIn("oob_label", ev.details)

    def test_noise_never_escalated_even_with_oob_available(self):
        eng2 = SSRFEngine(parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        }, oob_domain="abc.oast.fun", oob_correlation_path="/tmp/should-not-be-written-ssrf-test.jsonl")
        cand = eng2.generate_candidates({}, {})[0]
        from pipeline.detection.engine import Evidence
        ev = Evidence(candidate=cand, classification="NOISE", reason="test")
        eng2.adapter(cand, ev)
        self.assertFalse(os.path.isfile("/tmp/should-not-be-written-ssrf-test.jsonl"))


class TestAdapterWithRealOOBSession(unittest.TestCase):
    """The actual integration point with this pipeline's existing,
    already-working Interactsh setup (see
    pipeline/detection/adapters/interactsh.py) — same label formula and
    same oob_correlation.jsonl file/format AI Agent Phase 2 already
    writes, so the shared 'OOB Check' workflow step needs zero changes
    to pick this engine's registrations up too."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.correlation_path = os.path.join(self.tmp, "ai_agent", "oob_correlation.jsonl")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_lead_gets_registered_with_matching_label_formula(self):
        import hashlib
        fired_urls = []

        def prober(url):
            fired_urls.append(url)
            return {"status": 200, "body": "", "elapsed_ms": 10}

        eng = SSRFEngine(prober=prober, parameter_map={
            "endpoints": [{"endpoint": "https://x.com/fetch", "parameters": [{"name": "url", "sources": ["js"]}]}]
        }, oob_domain="abc123.oast.fun", oob_correlation_path=self.correlation_path)
        cand = eng.generate_candidates({}, {})[0]
        from pipeline.detection.engine import Evidence
        ev = Evidence(candidate=cand, classification="LEAD", reason="diff signal")
        out = eng.adapter(cand, ev)

        expected_label = hashlib.md5(
            b"https://x.com/fetch|url|ssrf|ssrf-v1"
        ).hexdigest()[:12]
        self.assertEqual(out.details["oob_label"], expected_label)

        with open(self.correlation_path) as f:
            rec = json.loads(f.readline())
        self.assertEqual(rec["label"], expected_label)
        self.assertEqual(rec["url"], "https://x.com/fetch")
        self.assertEqual(rec["param"], "url")
        self.assertEqual(rec["vuln_class"], "ssrf")

        # must have actually fired a request using {label}.{oob_domain}
        # as the payload — registering without firing would never
        # produce a real callback for "OOB Check" to find.
        self.assertTrue(any(f"{expected_label}.abc123.oast.fun" in u for u in fired_urls))

    def test_correlation_write_failure_does_not_crash(self):
        # A genuinely broken path: a plain FILE sitting where a
        # directory needs to be created — makedirs() cannot succeed
        # here (unlike a merely-nonexistent-but-creatable parent, which
        # this sandbox's permissions would happily create). Any OSError
        # here must degrade to the un-escalated LEAD, never take down
        # the engine.
        import tempfile
        blocker = os.path.join(self.tmp, "not_a_directory")
        with open(blocker, "w") as f:
            f.write("x")
        bad_path = os.path.join(blocker, "ai_agent", "oob_correlation.jsonl")
        eng = SSRFEngine(prober=lambda u: {"status": 200, "body": "", "elapsed_ms": 1},
                          parameter_map={
                              "endpoints": [{"endpoint": "https://x.com/fetch",
                                             "parameters": [{"name": "url", "sources": ["js"]}]}]
                          }, oob_domain="abc.oast.fun", oob_correlation_path=bad_path)
        cand = eng.generate_candidates({}, {})[0]
        from pipeline.detection.engine import Evidence
        ev = Evidence(candidate=cand, classification="LEAD", reason="test")
        out = eng.adapter(cand, ev)  # must not raise
        self.assertNotIn("oob_label", out.details)


class TestOnRealSuperdrugData(unittest.TestCase):
    """Same discipline as pattern_predictor.py and every other engine:
    prove candidate generation on real captured recon, not just
    synthetic fixtures."""

    def test_generates_candidates_from_real_parameter_intelligence(self):
        fixture_path = os.path.join(FIXTURE_DIR, "real_superdrug_parameter_intelligence.json")
        vocab_path = os.path.join(FIXTURE_DIR, "real_superdrug_vocabulary.json")
        if not (os.path.isfile(fixture_path) and os.path.isfile(vocab_path)):
            self.skipTest("real fixtures not present")
        pm = load_fixture("real_superdrug_parameter_intelligence.json")
        vocab = load_fixture("real_superdrug_vocabulary.json")
        eng = SSRFEngine(parameter_map=pm, max_candidates=9999)
        cands = eng.generate_candidates({}, vocab)
        self.assertGreater(len(cands), 0)
        # every candidate must trace back to a real observed endpoint+param
        real_endpoints = {e["endpoint"] for e in pm["endpoints"]}
        for c in cands:
            self.assertIn(c.metadata["endpoint"], real_endpoints)

    def test_wordpress_oembed_present_in_real_data(self):
        # This is the concrete real finding cited in ssrf_engine.py's
        # module docstring — assert it's still surfaced so a future
        # edit can't silently regress the exact case that justified
        # building this engine.
        fixture_path = os.path.join(FIXTURE_DIR, "real_superdrug_parameter_intelligence.json")
        if not os.path.isfile(fixture_path):
            self.skipTest("real fixture not present")
        pm = load_fixture("real_superdrug_parameter_intelligence.json")
        eng = SSRFEngine(parameter_map=pm, max_candidates=9999)
        cands = eng.generate_candidates({}, {})
        self.assertTrue(any("oembed" in c.target for c in cands))


if __name__ == "__main__":
    unittest.main()
