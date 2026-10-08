#!/usr/bin/env python3
import json, os, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import si2_canonicalize as si2

class SI2Canonicalize(unittest.TestCase):
    def test_dedupe_preserves_detectors(self):
        obs = [
            {"detector": "SecretFinder", "rule": "aws", "file": "a.js", "match_ref": "AKIA…"},
            {"detector": "Gitleaks", "rule": "aws-access-key", "file": "a.js", "match_ref": "AKIA…"},
            {"detector": "TruffleHog", "rule": "AWS", "file": "a.js", "match_ref": "AKIA…"},
        ]
        cands = si2.canonicalize(obs)
        self.assertEqual(len(cands), 1)
        self.assertEqual(set(cands[0]["detectors"]), {"SecretFinder", "Gitleaks", "TruffleHog"})
        self.assertEqual(cands[0]["classification"], "HIGH_SIGNAL")
        self.assertNotEqual(cands[0]["classification"], "CONFIRMED")
        self.assertEqual(len(cands[0]["provenance"]), 3)

    def test_different_files_not_merged(self):
        obs = [
            {"detector": "Gitleaks", "file": "a.js", "match_ref": "x"},
            {"detector": "Gitleaks", "file": "b.js", "match_ref": "x"},
        ]
        self.assertEqual(len(si2.canonicalize(obs)), 2)

if __name__ == "__main__":
    unittest.main()
