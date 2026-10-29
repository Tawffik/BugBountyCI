"""P2 integration: body samples, passive seeds, operator summary fields."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SmartFuzzP2(unittest.TestCase):
    def test_body_sampler_writes_summary(self):
        rd = Path(tempfile.mkdtemp())
        sf = rd / "smart-fuzzing"
        sf.mkdir(parents=True)
        (sf / "response_diffs.json").write_text(
            json.dumps(
                [
                    {
                        "url": "https://example.com/admin",
                        "classification": "INTERESTING",
                    }
                ]
            )
        )
        subprocess.check_call(
            [
                "python3",
                str(ROOT / "pipeline/smart-fuzzing/sample_interesting_bodies.py"),
                "--results-dir",
                str(rd),
                "--budget",
                "1",
            ]
        )
        self.assertTrue((sf / "body_samples_summary.json").is_file())
        s = json.loads((sf / "body_samples_summary.json").read_text())
        self.assertEqual(s["sampled"], 1)

    def test_operator_summary_includes_p2_fields(self):
        rd = Path(tempfile.mkdtemp())
        sf = rd / "smart-fuzzing"
        sf.mkdir(parents=True)
        (sf / "target_profile.json").write_text(
            json.dumps({"host_count": 1, "hosts_source": "live/hostname_targets.txt"})
        )
        (sf / "body_samples_summary.json").write_text(json.dumps({"sampled": 2}))
        (sf / "fallback_status.json").write_text(json.dumps({"used": True}))
        (sf / "interesting.txt").write_text("# header\n")
        subprocess.check_call(
            ["python3", str(ROOT / "pipeline/smart-fuzzing/write_operator_summary.py"), str(rd)]
        )
        s = json.loads((sf / "operator_summary.json").read_text())
        self.assertEqual(s.get("body_samples"), 2)
        self.assertTrue(s.get("fallback_used"))

    def test_sample_wired_in_launcher(self):
        sh = (ROOT / "scripts" / "smart_fuzzing.sh").read_text()
        self.assertIn("sample_interesting_bodies.py", sh)
        self.assertIn("write_operator_summary_safe", sh)


if __name__ == "__main__":
    unittest.main()
