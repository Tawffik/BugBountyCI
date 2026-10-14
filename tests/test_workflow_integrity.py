#!/usr/bin/env python3
"""Regression: zero-track-hunter.yml must remain a complete workflow, not a placeholder."""
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows" / "zero-track-hunter.yml"
MIN_BYTES = 100_000
REQUIRED_MARKERS = (
    "record_probe",
    "PROBE_CAP",
    "probe_results.jsonl",
    "enable_git_exposure",
    "Zero Track",
)
FORBIDDEN = (
    "SEE_FILE_TOO_LARGE",
    "SEE_FILE_TOO_LARGE_USE_PUSH_OR_SELF_HEAL",
)


class TestWorkflowIntegrity(unittest.TestCase):
    def test_file_exists_and_large(self):
        self.assertTrue(WF.is_file(), f"missing {WF}")
        size = WF.stat().st_size
        self.assertGreaterEqual(size, MIN_BYTES, f"workflow truncated: size={size}")

    def test_required_markers(self):
        text = WF.read_text(encoding="utf-8", errors="replace")
        for m in REQUIRED_MARKERS:
            self.assertIn(m, text, f"missing marker {m!r}")

    def test_no_placeholder(self):
        text = WF.read_text(encoding="utf-8", errors="replace")
        for bad in FORBIDDEN:
            self.assertNotIn(bad, text, f"placeholder present: {bad!r}")

    def test_yaml_loads(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        with open(WF, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        self.assertIsInstance(doc, dict)
        # PyYAML parses bare key "on:" as boolean True
        self.assertTrue("on" in doc or True in doc, "missing workflow triggers (on:)")
        self.assertIn("jobs", doc)
        jobs = doc["jobs"]
        self.assertIsInstance(jobs, dict)
        self.assertGreaterEqual(len(jobs), 1)


if __name__ == "__main__":
    unittest.main()
