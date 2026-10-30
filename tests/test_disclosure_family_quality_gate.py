"""Disclosure family honesty appears on QUALITY_GATE."""
from pathlib import Path
import json
import tempfile
import unittest

from scripts.build_quality_gate import build


class DisclosureFamilyGate(unittest.TestCase):
    def test_rollup_and_github_rate_limit(self):
        rd = Path(tempfile.mkdtemp())
        (rd / "github_exposure").mkdir(parents=True)
        (rd / "info_disclosure").mkdir(parents=True)
        (rd / "source_maps").mkdir(parents=True)
        (rd / "meta" / "phases").mkdir(parents=True)
        (rd / "github_exposure" / "summary.json").write_text(
            json.dumps({"overall": "RATE_LIMIT", "status": "RATE_LIMIT"})
        )
        (rd / "info_disclosure" / "archive_sensitive_summary.json").write_text(
            json.dumps({"probed": 3, "leads": 1})
        )
        (rd / "info_disclosure" / "probe_results.jsonl").write_text(
            json.dumps({"url": "https://x/a"}) + "\n"
        )
        (rd / "source_maps" / "found.txt").write_text("https://x/app.js.map\n")
        r = build(rd)
        codes = [f["code"] for f in r["findings"]]
        self.assertIn("disclosure_family_rollup", codes)
        self.assertIn("disclosure_github_provider", codes)
        roll = next(f for f in r["findings"] if f["code"] == "disclosure_family_rollup")
        self.assertIn("archive_probed=3", roll["detail"])
        self.assertIn("source_maps=1", roll["detail"])


if __name__ == "__main__":
    unittest.main()
