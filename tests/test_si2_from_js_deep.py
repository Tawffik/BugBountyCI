#!/usr/bin/env python3
import json, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import si2_from_js_deep as adapter
from si2_canonicalize import canonicalize

RESULTS = ROOT / "tests" / "fixtures" / "js_deep_results"

class JSDeepSI2Adapter(unittest.TestCase):
    def test_end_to_end_js_deep_to_canonical(self):
        obs = adapter.collect_js_deep(RESULTS)
        self.assertTrue(obs)
        # MODAL_KEYS filtered
        self.assertFalse(any("MODAL" in json.dumps(o) for o in obs))
        cands = canonicalize(obs)
        blob = json.dumps(cands)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)
        # multi-detector AWS should collapse
        high = [c for c in cands if c["classification"] == "HIGH_SIGNAL"]
        self.assertGreaterEqual(len(high), 1)
        multi = [c for c in cands if len(c["detectors"]) >= 2]
        self.assertGreaterEqual(len(multi), 1)

    def test_cli_writes_report(self):
        import subprocess
        out = Path(tempfile.mkdtemp()) / "secret_candidates.json"
        rc = subprocess.call([
            sys.executable, str(ROOT / "scripts" / "si2_from_js_deep.py"),
            "--results-dir", str(RESULTS), "--out", str(out),
        ])
        self.assertEqual(rc, 0)
        report = json.loads(out.read_text())
        self.assertEqual(report["schema"], "bugbountyci.secret_candidates.v1")
        self.assertGreater(report["observation_count"], 0)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out.read_text())

    def test_malformed_gitleaks(self):
        td = Path(tempfile.mkdtemp())
        (td / "gitleaks_findings.json").write_text("not-json")
        self.assertEqual(adapter.parse_gitleaks(td / "gitleaks_findings.json"), [])

if __name__ == "__main__":
    unittest.main()
