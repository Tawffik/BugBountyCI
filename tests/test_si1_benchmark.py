#!/usr/bin/env python3
import json, subprocess, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

class SI1Benchmark(unittest.TestCase):
    def test_oracle_structure(self):
        oracle = json.loads((ROOT / "tests/fixtures/si1/oracle.json").read_text())
        self.assertEqual(oracle["schema"], "bugbountyci.si1_oracle.v1")
        self.assertIn("inject", oracle)
        for c in oracle["cases"]:
            self.assertIn(c["label"], ("TP", "FP"))
            self.assertTrue((ROOT / "tests/fixtures/si1" / c["path"]).is_file())

    def test_no_contiguous_secrets_in_fixtures(self):
        root = ROOT / "tests/fixtures/si1"
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            t = p.read_text(errors="ignore")
            self.assertNotRegex(t, r"AKIA[0-9A-Z]{16}")
            self.assertNotRegex(t, r"ghp_[A-Za-z0-9]{20,}")
            self.assertNotRegex(t, r"xox[baprs]-[A-Za-z0-9-]{10,}")
            self.assertNotRegex(t, r"sk_(?:live|test)_[A-Za-z0-9]{10,}")

    def test_benchmark_gate(self):
        rc = subprocess.call([
            sys.executable, str(ROOT / "scripts/si1_benchmark.py"),
            "--fixtures", str(ROOT / "tests/fixtures/si1"),
            "--out", str(ROOT / "tests/fixtures/si1/benchmark_report.json"),
        ])
        self.assertEqual(rc, 0)
        report = json.loads((ROOT / "tests/fixtures/si1/benchmark_report.json").read_text())
        self.assertEqual(report["counts"]["fp"], 0)
        self.assertEqual(report["counts"]["fn"], 0)

if __name__ == "__main__":
    unittest.main()
