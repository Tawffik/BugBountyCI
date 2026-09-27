import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from pipeline.detection.engine import (
    EngineRunResult, Evidence, Candidate, write_phase_status, result_to_phase_status,
)


def _candidate():
    return Candidate(target="https://x.com/a", engine="test-engine")


class TestResultToPhaseStatus(unittest.TestCase):
    def test_did_not_run_is_skipped_starved(self):
        r = EngineRunResult(engine="e", ran=False, error="prerequisites not met")
        status, detail = result_to_phase_status(r)
        self.assertEqual(status, "skipped_starved")
        self.assertIn("prerequisites", detail)

    def test_crashed_is_error(self):
        r = EngineRunResult(engine="e", ran=True, error="Traceback: boom")
        status, detail = result_to_phase_status(r)
        self.assertEqual(status, "error")
        self.assertEqual(detail, "Traceback: boom")

    def test_zero_candidates_is_empty(self):
        r = EngineRunResult(engine="e", ran=True, candidates_generated=0)
        status, detail = result_to_phase_status(r)
        self.assertEqual(status, "empty")

    def test_candidates_but_all_noise_is_ok_not_empty(self):
        # Real distinction this closes (Gap J): candidates were tested,
        # nothing suspicious came back — that's a VALID result, not the
        # same as "zero candidates" (which means nothing was even
        # available to test).
        cand = _candidate()
        r = EngineRunResult(engine="e", ran=True, candidates_generated=14,
                             evidence=[Evidence(candidate=cand, classification="NOISE", reason="x")])
        status, detail = result_to_phase_status(r)
        self.assertEqual(status, "ok")
        self.assertIn("EMPTY_VALID", detail)

    def test_real_signal_is_ok_with_count(self):
        cand = _candidate()
        r = EngineRunResult(engine="e", ran=True, candidates_generated=60,
                             evidence=[
                                 Evidence(candidate=cand, classification="NOISE", reason="x"),
                                 Evidence(candidate=cand, classification="LEAD", reason="y"),
                             ])
        status, detail = result_to_phase_status(r)
        self.assertEqual(status, "ok")
        self.assertIn("non-NOISE=1", detail)


class TestWritePhaseStatus(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_writes_same_schema_as_bash_pipeline_lib(self):
        write_phase_status(self.tmp, "ssrf", "ok", "candidates=5")
        path = os.path.join(self.tmp, "meta", "phases", "ssrf.json")
        self.assertTrue(os.path.isfile(path))
        with open(path) as f:
            rec = json.load(f)
        # Same field names scripts/pipeline_lib.sh's write_phase_status
        # already produces for dns_resolve/live_probe/url_collection —
        # a health report must be able to read either language's output
        # with one code path.
        for field in ("phase", "status", "detail", "ts", "network_mode"):
            self.assertIn(field, rec)
        self.assertEqual(rec["phase"], "ssrf")
        self.assertEqual(rec["status"], "ok")

    def test_unwritable_path_does_not_raise(self):
        blocker = os.path.join(self.tmp, "not_a_dir")
        with open(blocker, "w") as f:
            f.write("x")
        bad_rd = os.path.join(blocker, "sub")
        write_phase_status(bad_rd, "ssrf", "ok", "x")  # must not raise


if __name__ == "__main__":
    unittest.main()
