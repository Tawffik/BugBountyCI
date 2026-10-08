#!/usr/bin/env python3
import json, os, sys, tempfile, unittest, subprocess

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class SraHandoffContract(unittest.TestCase):
    def test_builds_primary_host_and_endpoints(self):
        td = tempfile.mkdtemp()
        os.makedirs(os.path.join(td, "meta"))
        os.makedirs(os.path.join(td, "js_deep"))
        with open(os.path.join(td, "meta", "recon_export.json"), "w") as f:
            json.dump({"schema": "bugbountyci.recon_export.v1", "target": "example.com", "run_id": "t1"}, f)
        with open(os.path.join(td, "meta", "target_profile.json"), "w") as f:
            json.dump({"schema": "bugbountyci.target_profile.v1", "target": "example.com", "run_id": "t1"}, f)
        with open(os.path.join(td, "meta", "engine_health.json"), "w") as f:
            json.dump({"overall": "OK", "flags": []}, f)
        with open(os.path.join(td, "meta", "hosts.jsonl"), "w") as f:
            f.write(json.dumps({"host": "example.com"}) + "\n")
            f.write(json.dumps({"host": "api.example.com"}) + "\n")
        with open(os.path.join(td, "meta", "endpoints.jsonl"), "w") as f:
            f.write(json.dumps({"endpoint": "https://api.example.com/v1/users", "host": "api.example.com"}) + "\n")
        with open(os.path.join(td, "js_deep", "linkfinder_normalized.jsonl"), "w") as f:
            f.write(json.dumps({"classification": "API_ROUTE", "resolved_url": "https://api.example.com/v1/auth.login", "raw_value": "/v1/auth.login"}) + "\n")
            f.write(json.dumps({"classification": "STATIC_ASSET", "resolved_url": "https://example.com/app.js"}) + "\n")
        open(os.path.join(td, "meta", "urls.jsonl"), "w").close()
        open(os.path.join(td, "meta", "parameters.jsonl"), "w").close()
        rc = subprocess.call([sys.executable, os.path.join(ROOT, "scripts", "export_sra_handoff.py"), "--results-dir", td])
        self.assertEqual(rc, 0)
        doc = json.load(open(os.path.join(td, "meta", "sra_handoff.json")))
        self.assertEqual(doc["primary_host"], "example.com")
        self.assertTrue(doc["endpoints"])
        paths = {e["path"] for e in doc["endpoints"]}
        self.assertTrue(any(e["path"]=="/v1/users" or "users" in e["path"] for e in doc["endpoints"]))
        self.assertTrue(any("auth" in e["path"] for e in doc["endpoints"]))


def urlparse_path(doc):
    return ""


if __name__ == "__main__":
    unittest.main()
