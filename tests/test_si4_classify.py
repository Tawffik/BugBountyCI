#!/usr/bin/env python3
import json, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from si4_classify import classify_candidate, classify_report

class SI4Classify(unittest.TestCase):
    def test_google_captcha_benign(self):
        c = classify_candidate({
            "rules": ["google_captcha"], "match_ref": "google_captcha:len=40:fp=abc",
            "detectors": ["SecretFinder"], "classification": "LEAD", "confidence": 0.4, "provenance": [],
        })
        self.assertEqual(c["classification"], "LIKELY_BENIGN")
        self.assertEqual(c["candidate_type"], "public_client_identifier")
        self.assertNotEqual(c["classification"], "CONFIRMED")

    def test_long_possible_creds_code_fragment(self):
        c = classify_candidate({
            "rules": ["possible_Creds"], "match_ref": "possible_Creds:len=500:fp=x",
            "detectors": ["SecretFinder"], "classification": "LEAD", "confidence": 0.4, "provenance": [],
        })
        self.assertEqual(c["classification"], "LIKELY_BENIGN")
        self.assertEqual(c["candidate_type"], "code_fragment")

    def test_twilio_single_detector_lead(self):
        c = classify_candidate({
            "rules": ["twilio_account_sid"], "match_ref": "twilio_account_sid:len=34:fp=y",
            "detectors": ["SecretFinder"], "classification": "LEAD", "confidence": 0.4, "provenance": [],
        })
        self.assertEqual(c["classification"], "LEAD")
        self.assertEqual(c["provider"], "twilio")
        self.assertIn("client_js_often_embeds_public_account_sid", c["benign_indicators"])

    def test_multi_detector_high_signal(self):
        c = classify_candidate({
            "rules": ["aws-access-key"], "match_ref": "aws:len=20:fp=z",
            "detectors": ["SecretFinder", "Gitleaks"], "classification": "LEAD", "confidence": 0.4, "provenance": [],
        })
        self.assertEqual(c["classification"], "HIGH_SIGNAL")
        self.assertNotEqual(c["classification"], "CONFIRMED")

    def test_report_no_confirmed(self):
        rep = classify_report({"candidates": [{
            "rules": ["google_captcha"], "match_ref": "google_captcha:len=40:fp=a",
            "detectors": ["SecretFinder"], "classification": "LEAD", "confidence": 0.4, "provenance": [],
        }]})
        self.assertEqual(rep["by_class"].get("CONFIRMED", 0), 0)
        self.assertTrue(rep.get("si4"))

if __name__ == "__main__":
    unittest.main()
