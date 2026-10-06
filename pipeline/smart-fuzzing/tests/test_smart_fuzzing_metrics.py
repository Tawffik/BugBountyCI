#!/usr/bin/env python3
"""Contract tests: smart-fuzzing finding counts and ffuf aggregate states."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
import response_diff as rd  # noqa: E402
import fallback_gate as fg  # noqa: E402


class FindingCountTests(unittest.TestCase):
    def test_header_only_is_zero(self):
        td = tempfile.mkdtemp()
        p = os.path.join(td, "interesting.txt")
        with open(p, "w") as f:
            f.write("# RANKED RESPONSE SIGNALS\n# comment\n\n")
        self.assertEqual(rd.count_interesting_findings(p), 0)

    def test_header_plus_finding(self):
        td = tempfile.mkdtemp()
        p = os.path.join(td, "interesting.txt")
        with open(p, "w") as f:
            f.write("# hdr\nhttps://t.example/a [200] 10 bytes (INTERESTING)\n  reason\n")
        self.assertEqual(rd.count_interesting_findings(p), 1)


class FfufAggregateTests(unittest.TestCase):
    def test_executed_no_match(self):
        td = tempfile.mkdtemp()
        with open(os.path.join(td, "h.json"), "w") as f:
            json.dump({"results": [], "config": {"autocalibration": True}}, f)
        s = rd.aggregate_ffuf_raw(td)
        self.assertEqual(s["execution_state"], "REQUESTS_EXECUTED_NO_MATCH")
        self.assertEqual(s["raw_match_count"], 0)

    def test_matches_captured(self):
        td = tempfile.mkdtemp()
        with open(os.path.join(td, "h.json"), "w") as f:
            json.dump({"results": [{"url": "https://t/x", "status": 200, "length": 1}], "config": {"autocalibration": True}}, f)
        s = rd.aggregate_ffuf_raw(td)
        self.assertEqual(s["execution_state"], "MATCHES_CAPTURED")

    def test_no_output(self):
        td = tempfile.mkdtemp()
        s = rd.aggregate_ffuf_raw(td)
        self.assertEqual(s["execution_state"], "NO_FFUF_OUTPUT")


class FallbackGateMetricsTests(unittest.TestCase):
    def test_legacy_ok_header_lines_corrected_by_metrics(self):
        td = tempfile.mkdtemp()
        os.makedirs(os.path.join(td, "meta", "phases"), exist_ok=True)
        os.makedirs(os.path.join(td, "smart-fuzzing"), exist_ok=True)
        phase = os.path.join(td, "meta", "phases", "smart_fuzzing.json")
        with open(phase, "w") as f:
            json.dump({"status": "ok", "detail": "interesting_lines=5"}, f)
        with open(os.path.join(td, "smart-fuzzing", "metrics.json"), "w") as f:
            json.dump({"finding_count": 0, "pipeline_state": "REQUESTS_EXECUTED_NO_MATCH"}, f)
        run, reason = fg.should_run_common_txt_fallback(phase)
        self.assertFalse(run)
        self.assertEqual(reason, "empty_valid_metrics_zero_findings")


if __name__ == "__main__":
    unittest.main()

class CalibrationObservabilityTests(unittest.TestCase):
    def test_planned_vs_post_ac(self):
        td = tempfile.mkdtemp()
        os.makedirs(os.path.join(td, "smart-fuzzing"), exist_ok=True)
        with open(os.path.join(td, "smart-fuzzing", "wordlist_size.txt"), "w") as f:
            f.write("70\n")
        fd = os.path.join(td, "ffuf")
        os.makedirs(fd)
        with open(os.path.join(fd, "a.json"), "w") as f:
            json.dump({"results": [], "config": {"autocalibration": True}}, f)
        with open(os.path.join(fd, "b.json"), "w") as f:
            json.dump({"results": [], "config": {"autocalibration": True}}, f)
        s = rd.aggregate_ffuf_raw(fd, results_dir=td)
        self.assertEqual(s["planned_requests_ceiling"], 140)
        self.assertEqual(s["post_calibration_match_count"], 0)
        self.assertEqual(s["execution_state"], "REQUESTS_EXECUTED_NO_MATCH")
