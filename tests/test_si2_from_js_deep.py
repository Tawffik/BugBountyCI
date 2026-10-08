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

class PossibleCredsJSFragmentFilter(unittest.TestCase):
    def test_drops_long_js_snippet(self):
        from pathlib import Path
        import tempfile
        td = Path(tempfile.mkdtemp()) / "js_deep"
        td.mkdir()
        # long possible_Creds with JS markers — must drop
        noisy = "password" + "x" * 50 + ";let a=1;var b=2"
        (td / "secretfinder_secrets.txt").write_text(
            f"[app.js] possible_Creds\t->\t{noisy}\n"
            f"[app.js] possible_Creds\t->\tsecretvalue12345\n"  # short, preserve
            f"[app.js] AWS Access Key\t->\tAKIAIOSFODNN7EXAMPLE\n"
        )
        (td / "gitleaks_findings.json").write_text("[]")
        (td / "trufflehog_findings.jsonl").write_text("")
        (td / "mantra_findings.txt").write_text("")
        obs = adapter.collect_js_deep(td.parent)
        rules = [o.get("rule","") for o in obs]
        self.assertNotIn("possible_Creds", [r for r,o in zip(rules,obs) if "possible" in r.lower() and "AKIA" in str(o)])
        # short possible_Creds preserved
        pc = [o for o in obs if "possible" in (o.get("rule") or "").lower()]
        self.assertEqual(len(pc), 1)
        # AWS preserved
        self.assertTrue(any("AWS" in (o.get("rule") or "") for o in obs))

    def test_preserves_short_possible_creds(self):
        self.assertFalse(adapter._is_js_code_fragment("shortsecret12"))
        self.assertTrue(adapter._is_js_code_fragment("pass" + "x"*100 + ";let a=1"))

class TwilioSidShapeFilter(unittest.TestCase):
    def test_drops_non_ac_twilio_shaped(self):
        from pathlib import Path
        import tempfile
        td = Path(tempfile.mkdtemp()) / "js_deep"
        td.mkdir()
        fake = "ace-" + "x" * 30  # 34 chars, not AC...
        real = "AC" + ("a" * 32)
        (td / "secretfinder_secrets.txt").write_text(
            f"[a.js] twilio_account_sid\t->\t{fake}\n"
            f"[b.js] twilio_account_sid\t->\t{real}\n"
        )
        (td / "gitleaks_findings.json").write_text("[]")
        (td / "trufflehog_findings.jsonl").write_text("")
        (td / "mantra_findings.txt").write_text("")
        obs = adapter.collect_js_deep(td.parent)
        tw = [o for o in obs if "twilio" in (o.get("rule") or "").lower()]
        self.assertEqual(len(tw), 1)
        # real SID preserved via fingerprint path
        self.assertTrue(any(o.get("file") == "b.js" for o in tw))
