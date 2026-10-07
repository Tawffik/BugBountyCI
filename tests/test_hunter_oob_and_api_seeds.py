#!/usr/bin/env python3
"""Contract tests: OOB probe≠confirmed; LinkFinder API seeds Hunter INTERESTING."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "detection"))
import hunter_queue_builder as hq  # noqa: E402


class HunterIntelligenceContracts(unittest.TestCase):
    def test_oob_not_seen_rewrites_callback_language(self):
        td = tempfile.mkdtemp()
        os.makedirs(os.path.join(td, "ai_agent"))
        os.makedirs(os.path.join(td, "detection"))
        open(os.path.join(td, "ai_agent", "oob_findings.txt"), "w").write("")
        payload = [{
            "engine": "ssrf-v1",
            "evidence": [{
                "classification": "HIGH_SIGNAL",
                "reason": "diff; OOB callback registered (label=aabbccddeeff) x",
                "details": {"oob_label": "aabbccddeeff"},
                "candidate": {"target": "https://t/?url={PAYLOAD}"},
                "stable": True,
            }],
        }]
        open(os.path.join(td, "detection", "engine_results.json"), "w").write(json.dumps(payload))
        entries = hq.load_detection_evidence(td)
        self.assertEqual(len(entries), 1)
        self.assertIn("OOB_NOT_SEEN", entries[0]["reason"])
        self.assertNotIn("OOB callback registered", entries[0]["reason"])

    def test_oob_confirmed_when_label_in_findings(self):
        td = tempfile.mkdtemp()
        os.makedirs(os.path.join(td, "ai_agent"))
        os.makedirs(os.path.join(td, "detection"))
        open(os.path.join(td, "ai_agent", "oob_findings.txt"), "w").write(
            "[OOB-CONFIRMED] aabbccddeeff callback\n"
        )
        payload = [{
            "engine": "ssrf-v1",
            "evidence": [{
                "classification": "HIGH_SIGNAL",
                "reason": "diff",
                "details": {"oob_label": "aabbccddeeff"},
                "candidate": {"target": "https://t/?url={PAYLOAD}"},
                "stable": True,
            }],
        }]
        open(os.path.join(td, "detection", "engine_results.json"), "w").write(json.dumps(payload))
        entries = hq.load_detection_evidence(td)
        self.assertIn("OOB_CONFIRMED", entries[0]["reason"])

    def test_linkfinder_api_seeds_interesting(self):
        td = tempfile.mkdtemp()
        os.makedirs(os.path.join(td, "js_deep"))
        rows = [
            {"classification": "API_ROUTE", "resolved_url": "https://api.example.com/v1/users", "source_js": "a.js"},
            {"classification": "STATIC_ASSET", "resolved_url": "https://example.com/app.js", "source_js": "a.js"},
            {"classification": "API_ROUTE", "raw_value": "/v1/api/auth.login", "source_js": "b.js"},
        ]
        with open(os.path.join(td, "js_deep", "linkfinder_normalized.jsonl"), "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        entries = hq.load_linkfinder_api_routes(td, limit=10)
        self.assertEqual(len(entries), 2)
        self.assertTrue(all(e["priority_class"] == "INTERESTING" for e in entries))
        self.assertTrue(all(e["engine"] == "linkfinder_api" for e in entries))


if __name__ == "__main__":
    unittest.main()
