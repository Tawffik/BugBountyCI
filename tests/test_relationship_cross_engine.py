#!/usr/bin/env python3
"""Cross-engine relationship types: HISTORICAL∩JS + secret→file."""
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class CrossEngineRelationships(unittest.TestCase):
    def test_secret_candidate_to_js_file_edge(self):
        td = Path(tempfile.mkdtemp())
        (td / "meta").mkdir()
        (td / "js_deep").mkdir()
        (td / "urls").mkdir()
        (td / "info_disclosure").mkdir()
        (td / "meta" / "secret_candidates_si4.json").write_text(json.dumps({
            "candidates": [{"candidate_id": "sec_abc", "file": "app.js", "classification": "LEAD"}]
        }))
        (td / "js_deep" / "linkfinder_normalized.jsonl").write_text(
            json.dumps({"classification": "WEB_ROUTE", "raw_value": "/apply", "source_js": "x.js"}) + "\n"
        )
        (td / "urls" / "wayback.txt").write_text("https://example.com/apply\n")
        env = os.environ.copy()
        env["TARGET"] = "example.com"
        env["TIMESTAMP"] = "test"
        rc = subprocess.call([sys.executable, str(ROOT / "scripts" / "write_pipeline_exports.py"), str(td)], env=env)
        self.assertEqual(rc, 0)
        rels = [json.loads(l) for l in (td / "meta" / "relationships.jsonl").read_text().splitlines()]
        types = {r["type"] for r in rels}
        self.assertIn("SECRET_CANDIDATE_TO_JS_FILE", types)
        self.assertIn("HISTORICAL_PATH_AND_JS_API", types)

if __name__ == "__main__":
    unittest.main()
