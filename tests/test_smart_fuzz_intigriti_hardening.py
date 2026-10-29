"""Regression: Intigriti hardening must not regress silent failures."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SmartFuzzHardening(unittest.TestCase):
    def test_operator_summary_runs_before_exit(self):
        sh = (ROOT / "scripts" / "smart_fuzzing.sh").read_text(encoding="utf-8")
        self.assertIn("write_operator_summary_safe", sh)
        # Every exit 0 should be preceded nearby by summary call
        lines = sh.splitlines()
        for i, line in enumerate(lines):
            if line.strip() == "exit 0":
                window = "\n".join(lines[max(0, i - 3) : i + 1])
                self.assertIn(
                    "write_operator_summary_safe",
                    window,
                    f"exit 0 at line {i+1} without summary",
                )

    def test_hostname_first_prefers_named_hosts(self):
        rd = Path(tempfile.mkdtemp())
        (rd / "live").mkdir()
        (rd / "js").mkdir()
        (rd / "js_deep").mkdir()
        (rd / "urls").mkdir()
        (rd / "targeted").mkdir()
        (rd / "live" / "hostname_targets.txt").write_text(
            "https://app.example.com\n", encoding="utf-8"
        )
        (rd / "live" / "live.txt").write_text("http://203.0.113.10\n", encoding="utf-8")
        subprocess.check_call(
            [
                "python3",
                str(ROOT / "pipeline" / "smart-fuzzing" / "target_profile.py"),
                "--results-dir",
                str(rd),
                "--target",
                "example.com",
            ]
        )
        prof = json.loads((rd / "smart-fuzzing" / "target_profile.json").read_text())
        self.assertTrue(any("app.example.com" in h for h in prof["hosts"]))
        self.assertFalse(any("203.0.113.10" in h for h in prof["hosts"]))
        self.assertIn("hostname", str(prof.get("hosts_source") or ""))

    def test_wolf_unavailable_status_file(self):
        rd = Path(tempfile.mkdtemp())
        (rd / "smart-fuzzing").mkdir(parents=True)
        profile = {
            "technologies": [],
            "api_present": False,
        }
        (rd / "smart-fuzzing" / "target_profile.json").write_text(json.dumps(profile))
        subprocess.check_call(
            [
                "python3",
                str(ROOT / "pipeline" / "smart-fuzzing" / "wolf_selector.py"),
                "--wolf-dir",
                "/tmp/definitely-missing-wolf-dir",
                "--target-profile",
                str(rd / "smart-fuzzing" / "target_profile.json"),
                "--results-dir",
                str(rd),
                "--mode",
                "normal",
            ]
        )
        st = json.loads((rd / "smart-fuzzing" / "wolf_status.json").read_text())
        self.assertEqual(st["status"], "WOLF_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
