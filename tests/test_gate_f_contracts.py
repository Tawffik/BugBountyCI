#!/usr/bin/env python3
"""Gate F — minimal offline contracts for intelligence honesty."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class GateFContracts(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.td, "js_deep"))
        os.makedirs(os.path.join(self.td, "smart-fuzzing", "ffuf_raw"))
        os.makedirs(os.path.join(self.td, "meta", "phases"))
        os.makedirs(os.path.join(self.td, "nuclei"))
        with open(os.path.join(self.td, "js_deep", "linkfinder_endpoints.txt"), "w") as f:
            f.write("[a.js] ./chunk.js\n[a.js] /api/users\n")
        with open(os.path.join(self.td, "smart-fuzzing", "interesting.txt"), "w") as f:
            f.write("# header only\n\n")
        with open(os.path.join(self.td, "smart-fuzzing", "ffuf_raw", "h.json"), "w") as f:
            json.dump({"results": [], "config": {"autocalibration": True}}, f)
        with open(os.path.join(self.td, "smart-fuzzing", "wordlist_size.txt"), "w") as f:
            f.write("5\n")
        with open(os.path.join(self.td, "meta", "phases", "nuclei.json"), "w") as f:
            json.dump({"status": "partial", "detail": "findings=0, requests=10, errors=8, error_rate=80"}, f)
        with open(os.path.join(self.td, "meta", "engine_health.json"), "w") as f:
            json.dump({"overall": "DEGRADED", "flags": ["Nuclei phase=PARTIAL — error_rate=80"]}, f)

    def test_linkfinder_raw_not_equal_api(self):
        subprocess.check_call(
            [sys.executable, os.path.join(ROOT, "scripts", "normalize_linkfinder.py"),
             "--results-dir", self.td, "--target", "example.com"],
            cwd=ROOT,
        )
        s = json.load(open(os.path.join(self.td, "js_deep", "linkfinder_summary.json")))
        self.assertEqual(s["raw_lines"], 2)
        self.assertEqual(s["api_routes"], 1)
        self.assertEqual(s["static_assets"], 1)
        self.assertNotEqual(s["raw_lines"], s["api_routes"])

    def test_nuclei_degraded_not_clean(self):
        subprocess.check_call(
            [sys.executable, os.path.join(ROOT, "scripts", "nuclei_track_summary.py"),
             "--results-dir", self.td],
            cwd=ROOT,
        )
        t = json.load(open(os.path.join(self.td, "meta", "nuclei_track.json")))
        self.assertEqual(t["track_state"], "DEGRADED")
        self.assertEqual(t["findings_count"], 0)

    def test_smart_fuzz_header_not_finding(self):
        subprocess.check_call(
            [sys.executable, os.path.join(ROOT, "pipeline", "smart-fuzzing", "response_diff.py"),
             "--results-dir", self.td,
             "--ffuf-json-dir", os.path.join(self.td, "smart-fuzzing", "ffuf_raw")],
            cwd=ROOT,
        )
        m = json.load(open(os.path.join(self.td, "smart-fuzzing", "metrics.json")))
        self.assertEqual(m["finding_count"], 0)
        self.assertEqual(m["pipeline_state"], "REQUESTS_EXECUTED_NO_MATCH")
        self.assertGreater(m["ffuf"]["planned_requests_ceiling"], 0)


if __name__ == "__main__":
    unittest.main()
