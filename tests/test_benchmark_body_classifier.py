#!/usr/bin/env python3
"""Body-classifier benchmark extension — controlled fixtures only."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "benchmark_info_disclosure"
SCRIPT = ROOT / "scripts" / "write_pipeline_exports.py"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "pipeline" / "detection"))

from classify_info_disclosure_body import classify_fixed_path_body  # noqa: E402
import hunter_queue_builder as hqb  # noqa: E402


def _run_exports(rd: Path) -> None:
    env = os.environ.copy()
    env["TARGET"] = "lab.example.com"
    env["TIMESTAMP"] = "bench"
    subprocess.check_call([sys.executable, str(SCRIPT), str(rd)], env=env, cwd=str(ROOT))


def _seed(rd: Path) -> None:
    for d in ("live", "urls", "js", "info_disclosure", "meta/phases"):
        (rd / d).mkdir(parents=True, exist_ok=True)
    (rd / "live" / "live.txt").write_text("https://lab.example.com\n")
    (rd / "urls" / "all.txt").write_text("https://lab.example.com/\n")
    (rd / "meta" / "phases" / "seed.json").write_text(json.dumps({"phase": "seed", "status": "ok"}))


class BodyClassifierBenchmark(unittest.TestCase):
    def test_classifier_unit_positives(self):
        cases = [
            ("/.git/HEAD", "ref: refs/heads/main\n", "CONTENT_SUPPORTED"),
            ("/.git/config", open(FIXTURES / "bodies" / "git_config_valid.txt").read(), "CONTENT_SUPPORTED"),
            ("/.env", open(FIXTURES / "bodies" / "env_valid.txt").read(), "CONTENT_SUPPORTED"),
            ("/backup.sql", open(FIXTURES / "bodies" / "backup_sql.txt").read(), "CONTENT_SUPPORTED"),
        ]
        for path, body, exp in cases:
            clf = classify_fixed_path_body(path, body)
            self.assertEqual(clf["disposition"], exp, msg=f"{path}: {clf}")
            self.assertTrue(clf["never_confirmed"])
            self.assertNotEqual(clf["disposition"], "CONFIRMED")

    def test_classifier_unit_hard_negatives(self):
        cases = [
            ("/.git/HEAD", open(FIXTURES / "bodies" / "spa.html").read(), "SPA_CATCHALL"),
            ("/.env", open(FIXTURES / "bodies" / "waf.html").read(), "WAF_CHALLENGE"),
            ("/.env", open(FIXTURES / "bodies" / "auth.html").read(), "AUTH_WALL"),
            ("/.env", open(FIXTURES / "bodies" / "placeholder_env.txt").read(), "PLACEHOLDER_ONLY"),
            ("/.git/HEAD", None, "PATH_LEAD"),
        ]
        for path, body, exp in cases:
            clf = classify_fixed_path_body(path, body)
            self.assertEqual(clf["disposition"], exp, msg=f"{path}: {clf}")
            self.assertFalse(clf.get("is_content_supported"))

    def test_classifier_ambiguous(self):
        self.assertEqual(classify_fixed_path_body("/.env", "")["disposition"], "EMPTY_BODY")
        self.assertEqual(
            classify_fixed_path_body("/.git/HEAD", "Hello world not a ref\n")["disposition"],
            "MALFORMED",
        )

    def test_path_only_never_confirmed_in_pipeline(self):
        rd = Path(tempfile.mkdtemp()) / "results"
        _seed(rd)
        (rd / "info_disclosure" / "git_exposure.txt").write_text(
            "[GIT-EXPOSURE] https://lab.example.com/.git/HEAD\n"
        )
        # no probe_results
        _run_exports(rd)
        obs = [json.loads(l) for l in open(rd / "meta" / "observations.jsonl") if l.strip()]
        git_obs = [o for o in obs if o.get("engine") == "info_disclosure_git"]
        self.assertTrue(git_obs)
        for o in git_obs:
            self.assertNotEqual((o.get("classification") or "").upper(), "CONFIRMED")
            self.assertEqual(o.get("disposition"), "PATH_LEAD")
            self.assertEqual(o.get("observed_behavior"), "path_lead_body_unavailable")

    def test_integration_positives_with_bodies(self):
        rd = Path(tempfile.mkdtemp()) / "results"
        _seed(rd)
        shutil.copy(FIXTURES / "positives" / "git_exposure.txt", rd / "info_disclosure" / "git_exposure.txt")
        shutil.copy(FIXTURES / "positives" / "config_files.txt", rd / "info_disclosure" / "config_files.txt")
        shutil.copy(FIXTURES / "positives" / "backup_files.txt", rd / "info_disclosure" / "backup_files.txt")
        shutil.copy(FIXTURES / "positives" / "probe_results.jsonl", rd / "info_disclosure" / "probe_results.jsonl")
        _run_exports(rd)
        obs = [json.loads(l) for l in open(rd / "meta" / "observations.jsonl") if l.strip()]
        content = [o for o in obs if o.get("observed_behavior") == "content_supported_candidate"]
        self.assertGreaterEqual(len(content), 3, msg=f"obs={obs}")
        for o in content:
            self.assertEqual(o.get("classification"), "LEAD")
            self.assertEqual(o.get("disposition"), "CONTENT_SUPPORTED")
        hunter = hqb.load_fixed_path_info_disclosure(str(rd))
        interesting = [h for h in hunter if h.get("priority_class") == "INTERESTING"]
        self.assertGreaterEqual(len(interesting), 3)
        for h in interesting:
            self.assertIn("CONTENT_SUPPORTED", h.get("reason", "") + str(h.get("details")))

    def test_integration_hard_neg_bodies_not_interesting(self):
        rd = Path(tempfile.mkdtemp()) / "results"
        _seed(rd)
        shutil.copy(FIXTURES / "hard_negatives" / "git_exposure.txt", rd / "info_disclosure" / "git_exposure.txt")
        shutil.copy(FIXTURES / "hard_negatives" / "config_files.txt", rd / "info_disclosure" / "config_files.txt")
        shutil.copy(FIXTURES / "hard_negatives" / "probe_results.jsonl", rd / "info_disclosure" / "probe_results.jsonl")
        _run_exports(rd)
        obs = [json.loads(l) for l in open(rd / "meta" / "observations.jsonl") if l.strip()]
        # SPA/WAF should be non_exposure behaviors
        for o in obs:
            self.assertNotEqual((o.get("classification") or "").upper(), "CONFIRMED")
            if "spa.example" in (o.get("url") or ""):
                self.assertIn("non_exposure", o.get("observed_behavior") or "")
                self.assertEqual(o.get("disposition"), "SPA_CATCHALL")
        hunter = hqb.load_fixed_path_info_disclosure(str(rd))
        # non-exposure must not appear as INTERESTING
        for h in hunter:
            self.assertNotIn("SPA_CATCHALL", str(h.get("details")))
            self.assertNotEqual(h.get("details", {}).get("disposition"), "SPA_CATCHALL")
            self.assertNotEqual(h.get("details", {}).get("disposition"), "WAF_CHALLENGE")
            self.assertNotEqual(h.get("details", {}).get("disposition"), "AUTH_WALL")
            self.assertNotEqual(h.get("details", {}).get("disposition"), "PLACEHOLDER_ONLY")


if __name__ == "__main__":
    unittest.main(verbosity=2)
