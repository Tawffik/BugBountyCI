#!/usr/bin/env python3
import os, sys, json, tempfile, unittest
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "detection"))
import hunter_queue_builder as hq


class HunterUsefulnessContracts(unittest.TestCase):
    def test_scheme_only_redirect_detected(self):
        self.assertTrue(hq._is_scheme_only_redirect(
            "http://capital.com/foo",
            "https://capital.com:443/foo",
        ))
        self.assertFalse(hq._is_scheme_only_redirect(
            "http://capital.com/foo",
            "https://capital.com/bar",
        ))

    def test_scheme_only_not_in_hunter_entries(self):
        td = tempfile.mkdtemp()
        os.makedirs(os.path.join(td, "info_disclosure"))
        rows = [
            {
                "outcome": "REDIRECTED",
                "validation_url": "http://example.com/a",
                "location": "https://example.com:443/a",
                "status": 301,
                "historical_source": "wayback.txt",
                "evidence_ladder": "CANDIDATE",
                "next_pivot": "inspect",
            },
            {
                "outcome": "CURRENTLY_REACHABLE",
                "validation_url": "https://example.com/api/v1",
                "location": "",
                "status": 200,
                "historical_source": "wayback.txt",
                "evidence_ladder": "CANDIDATE",
                "next_pivot": "inspect",
            },
        ]
        with open(os.path.join(td, "info_disclosure", "historical_validations.jsonl"), "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        entries = hq.load_historical_validations(td)
        self.assertEqual(len(entries), 1)
        self.assertIn("api/v1", entries[0]["target"])


if __name__ == "__main__":
    unittest.main()
