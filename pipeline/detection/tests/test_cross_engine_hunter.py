#!/usr/bin/env python3
import json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import hunter_queue_builder as hq

class CrossEngineHunter(unittest.TestCase):
    def test_loads_historical_preferred_and_excludes_secret(self):
        td = Path(tempfile.mkdtemp())
        (td / "meta").mkdir()
        (td / "meta" / "relationships.jsonl").write_text(
            json.dumps({"type": "JS_API_AND_LIVE_ENDPOINT", "from": "js_path:/api", "to": "endpoint:/api", "engines": ["linkfinder", "endpoint_model"], "provenance": "t"}) + "\n"
            + json.dumps({"type": "HISTORICAL_PATH_AND_JS_API", "from": "historical_path:/x", "to": "js_api:/x", "engines": ["historical", "linkfinder"], "provenance": "t"}) + "\n"
            + json.dumps({"type": "SECRET_CANDIDATE_TO_JS_FILE", "from": "secret:1", "to": "js_file:a.js"}) + "\n"
        )
        entries = hq.load_cross_engine_relationships(str(td), limit=40)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["details"]["relationship_type"], "HISTORICAL_PATH_AND_JS_API")
        self.assertEqual(entries[1]["details"]["relationship_type"], "JS_API_AND_LIVE_ENDPOINT")

    def test_exclude_targets_already_in_queue(self):
        td = Path(tempfile.mkdtemp())
        (td / "meta").mkdir()
        (td / "meta" / "relationships.jsonl").write_text(
            json.dumps({"type": "HISTORICAL_PATH_AND_JS_API", "from": "historical_path:/dup", "to": "js_api:/dup", "engines": ["historical", "linkfinder"], "provenance": "t"}) + "\n"
        )
        entries = hq.load_cross_engine_relationships(str(td), exclude_targets={"/dup"})
        self.assertEqual(entries, [])

if __name__ == "__main__":
    unittest.main()
