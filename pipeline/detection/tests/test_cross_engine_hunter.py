#!/usr/bin/env python3
import json, os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import hunter_queue_builder as hq

class CrossEngineHunter(unittest.TestCase):
    def test_loads_historical_js_only(self):
        td = Path(tempfile.mkdtemp())
        (td / "meta").mkdir()
        (td / "meta" / "relationships.jsonl").write_text(
            json.dumps({"type": "HISTORICAL_PATH_AND_JS_API", "from": "historical_path:/x", "to": "js_api:/x", "engines": ["historical", "linkfinder"], "provenance": "t"}) + "\n"
            + json.dumps({"type": "SECRET_CANDIDATE_TO_JS_FILE", "from": "secret:1", "to": "js_file:a.js"}) + "\n"
        )
        entries = hq.load_cross_engine_relationships(str(td))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["priority_class"], "RESEARCH_CONTEXT")
        self.assertEqual(entries[0]["engine"], "relationship_cross_engine")
        self.assertIn("Not a vulnerability", entries[0]["reason"])

if __name__ == "__main__":
    unittest.main()
