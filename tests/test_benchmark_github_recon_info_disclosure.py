#!/usr/bin/env python3
"""Independent controlled-fixture benchmark for GitHub recon + fixed-path info disclosure.

Ground-truth labels live in expected_labels.json and are NOT derived from detector output.
Tests the production write_pipeline_exports + hunter_queue_builder integration boundary.
Requires no network, no tokens, no live targets.

Report metrics as controlled-fixture performance only — not production FP/recall.
"""
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
LABELS = json.loads((FIXTURES / "expected_labels.json").read_text())
SCRIPT = ROOT / "scripts" / "write_pipeline_exports.py"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pipeline" / "detection"))

import hunter_queue_builder as hqb  # noqa: E402


def _run_exports(rd: Path, target: str = "lab.example.com") -> None:
    env = os.environ.copy()
    env["TARGET"] = target
    env["TIMESTAMP"] = "bench"
    subprocess.check_call(
        [sys.executable, str(SCRIPT), str(rd)],
        env=env,
        cwd=str(ROOT),
    )


def _seed_minimal(rd: Path) -> None:
    for d in ("live", "urls", "js", "info_disclosure", "meta/phases", "detection"):
        (rd / d).mkdir(parents=True, exist_ok=True)
    (rd / "live" / "live.txt").write_text("https://lab.example.com\n")
    (rd / "urls" / "all.txt").write_text("https://lab.example.com/\n")
    (rd / "meta" / "phases" / "seed.json").write_text(
        json.dumps({"phase": "seed", "status": "ok"})
    )


def _load_obs(rd: Path) -> list[dict]:
    p = rd / "meta" / "observations.jsonl"
    if not p.is_file():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def _obs_matching(obs: list[dict], fragment: str) -> list[dict]:
    frag = fragment.lower()
    return [o for o in obs if frag in (o.get("url") or "").lower() or frag in json.dumps(o).lower()]


class BenchmarkInfoDisclosure(unittest.TestCase):
    """Controlled-fixture benchmark — denominators in setUpClass metrics."""

    metrics: dict

    @classmethod
    def setUpClass(cls):
        cls.metrics = {
            "positives_expected": 0,
            "positives_detected": 0,
            "positives_missed": [],
            "hard_neg_expected_reject": 0,
            "hard_neg_correct": 0,
            "hard_neg_incorrect_promoted": [],
            "failure_cases_ok": 0,
            "failure_cases_fail": [],
            "schema_ok": 0,
            "schema_fail": 0,
            "provenance_ok": 0,
            "provenance_fail": [],
            "confirmed_forbidden_violations": [],
            "hunter_delivery_ok": 0,
            "hunter_delivery_fail": [],
        }

    def _base_rd(self) -> Path:
        rd = Path(tempfile.mkdtemp()) / "results"
        _seed_minimal(rd)
        return rd

    def test_01_positives_github_and_fixed_path(self):
        rd = self._base_rd()
        shutil.copy(FIXTURES / "positives" / "github_recon.txt", rd / "js" / "github_recon.txt")
        shutil.copy(FIXTURES / "positives" / "github_recon_raw.txt", rd / "js" / "github_recon_raw.txt")
        shutil.copy(FIXTURES / "positives" / "git_exposure.txt", rd / "info_disclosure" / "git_exposure.txt")
        shutil.copy(FIXTURES / "positives" / "config_files.txt", rd / "info_disclosure" / "config_files.txt")
        shutil.copy(FIXTURES / "positives" / "backup_files.txt", rd / "info_disclosure" / "backup_files.txt")
        _run_exports(rd)
        obs = _load_obs(rd)
        hunter = hqb.load_fixed_path_info_disclosure(str(rd))

        # schema
        for o in obs:
            if o.get("engine") in (
                "github_code_search",
                "info_disclosure_git",
                "info_disclosure_config",
                "info_disclosure_backup",
            ):
                if o.get("schema") == "bugbountyci.observation.v1" and o.get("provenance"):
                    self.metrics["schema_ok"] += 1
                else:
                    self.metrics["schema_fail"] += 1

        # summary / health
        summary = json.loads((rd / "meta" / "github_recon_summary.json").read_text())
        self.assertEqual(summary.get("kept_hits"), 3)
        self.assertEqual(summary.get("dorking_engine_status"), "IMPLEMENTED_NOT_INVOKED")
        eh = json.loads((rd / "meta" / "engine_health.json").read_text())
        gh_phase = (eh.get("phases") or {}).get("github_recon") or {}
        self.assertIn(gh_phase.get("status"), ("SUCCESS", "EMPTY_VALID"))

        cases = [c for c in LABELS["cases"] if c["class"] == "positive"]
        for c in cases:
            self.metrics["positives_expected"] += 1
            frag = c["input"].split("::")[-1].strip() if "::" in c["input"] else c["input"]
            # use distinctive substring
            keys = {
                "pos_gh_db_config": "database.yml",
                "pos_gh_env": ".env.production",
                "pos_git_head": ".git/HEAD",
                "pos_config_env": "[CONFIG]",
                "pos_backup": "backup.sql",
            }
            key = keys.get(c["id"], frag[:30])
            matched = _obs_matching(obs, key)
            if c.get("expected_observation"):
                if matched:
                    self.metrics["positives_detected"] += 1
                    o0 = matched[0]
                    self.assertNotEqual(
                        (o0.get("classification") or "").upper(),
                        "CONFIRMED",
                        msg="must never confirm from path/status alone",
                    )
                    if o0.get("classification") == "CONFIRMED":
                        self.metrics["confirmed_forbidden_violations"].append(c["id"])
                    for p in c.get("provenance_must_include") or []:
                        blob = json.dumps(o0)
                        if p in blob or p in (o0.get("provenance") or "") or p in (o0.get("engine") or ""):
                            self.metrics["provenance_ok"] += 1
                        else:
                            self.metrics["provenance_fail"].append((c["id"], p))
                else:
                    self.metrics["positives_missed"].append(c["id"])
                    self.fail(f"positive missed: {c['id']}")
            if c.get("expected_hunter"):
                hmatch = [h for h in hunter if key.lower() in (h.get("target") or "").lower()
                          or key.lower() in json.dumps(h).lower()]
                if hmatch and hmatch[0].get("priority_class") == "INTERESTING":
                    self.metrics["hunter_delivery_ok"] += 1
                else:
                    self.metrics["hunter_delivery_fail"].append(c["id"])
                    self.fail(f"hunter miss: {c['id']}")

    def test_02_hard_negatives_github_docs_placeholder(self):
        """Hard negatives must not become observations (desired) or at least never CONFIRMED."""
        rd = self._base_rd()
        shutil.copy(FIXTURES / "hard_negatives" / "github_recon.txt", rd / "js" / "github_recon.txt")
        shutil.copy(FIXTURES / "hard_negatives" / "github_recon_raw.txt", rd / "js" / "github_recon_raw.txt")
        _run_exports(rd)
        obs = _load_obs(rd)
        gh_obs = [o for o in obs if o.get("engine") == "github_code_search"]

        cases = [c for c in LABELS["cases"] if c["id"] in (
            "neg_docs_password_word", "neg_placeholder_key", "neg_public_robots"
        )]
        for c in cases:
            self.metrics["hard_neg_expected_reject"] += 1
            keys = {
                "neg_docs_password_word": "security.md",
                "neg_placeholder_key": "YOUR_API_KEY_HERE",
                "neg_public_robots": "robots.txt",
            }
            key = keys[c["id"]]
            matched = _obs_matching(gh_obs, key)
            # Never CONFIRMED
            for o in matched:
                self.assertNotEqual((o.get("classification") or "").upper(), "CONFIRMED")
            if c.get("expected_observation") is False:
                if not matched:
                    self.metrics["hard_neg_correct"] += 1
                else:
                    self.metrics["hard_neg_incorrect_promoted"].append(c["id"])
                    self.fail(f"hard negative incorrectly promoted: {c['id']}")

        # fixed-path SPA path hit: may be LEAD but never CONFIRMED
        rd2 = self._base_rd()
        shutil.copy(FIXTURES / "hard_negatives" / "git_exposure.txt", rd2 / "info_disclosure" / "git_exposure.txt")
        _run_exports(rd2)
        obs2 = _load_obs(rd2)
        for o in obs2:
            if o.get("engine") == "info_disclosure_git":
                self.assertNotEqual((o.get("classification") or "").upper(), "CONFIRMED")
                self.assertEqual(o.get("classification"), "LEAD")
                self.metrics["hard_neg_correct"] += 1
                self.metrics["hard_neg_expected_reject"] += 1

    def test_03_failure_missing_github_artifacts_not_run(self):
        rd = self._base_rd()
        # no github_recon files
        _run_exports(rd)
        summary = json.loads((rd / "meta" / "github_recon_summary.json").read_text())
        self.assertEqual(summary.get("raw_hits"), 0)
        self.assertEqual(summary.get("kept_hits"), 0)
        eh = json.loads((rd / "meta" / "engine_health.json").read_text())
        st = ((eh.get("phases") or {}).get("github_recon") or {}).get("status")
        self.assertEqual(st, "NOT_RUN", msg="missing artifacts must be NOT_RUN not SUCCESS zero")
        if st == "NOT_RUN":
            self.metrics["failure_cases_ok"] += 1
        else:
            self.metrics["failure_cases_fail"].append("fail_missing_github_artifacts")

    def test_04_failure_empty_kept(self):
        rd = self._base_rd()
        (rd / "js" / "github_recon.txt").write_text("")
        (rd / "js" / "github_recon_raw.txt").write_text("")
        _run_exports(rd)
        eh = json.loads((rd / "meta" / "engine_health.json").read_text())
        st = ((eh.get("phases") or {}).get("github_recon") or {}).get("status")
        # empty present files → EMPTY_VALID (ran, zero kept)
        self.assertIn(st, ("EMPTY_VALID", "SUCCESS"))
        # must not claim candidates
        obs = [o for o in _load_obs(rd) if o.get("engine") == "github_code_search"]
        self.assertEqual(len(obs), 0)
        self.metrics["failure_cases_ok"] += 1

    def test_05_duplicate_lines_do_not_inflate(self):
        rd = self._base_rd()
        line = "lab-org/config-leak :: config/database.yml\n"
        (rd / "js" / "github_recon.txt").write_text(line + line + line)
        (rd / "js" / "github_recon_raw.txt").write_text(line + line)
        _run_exports(rd)
        obs = _obs_matching(_load_obs(rd), "database.yml")
        # production may emit one obs per line currently — measure uniqueness by url
        urls = [o.get("url") for o in obs]
        unique = set(urls)
        # Accept unique count == 1 as pass; if >1 record as gap for fix
        self.metrics["hard_neg_expected_reject"] += 1
        self.assertEqual(len(unique), 1, msg=f"duplicate lines inflated unique obs: {urls}")
        self.assertGreaterEqual(len(obs), 1)
        self.metrics["hard_neg_correct"] += 1
        for o in obs:
            self.assertNotEqual((o.get("classification") or "").upper(), "CONFIRMED")

    def test_06_recon_export_index_compatible(self):
        rd = self._base_rd()
        shutil.copy(FIXTURES / "positives" / "github_recon.txt", rd / "js" / "github_recon.txt")
        _run_exports(rd)
        # engine_health and recon_export if present must remain readable
        eh = json.loads((rd / "meta" / "engine_health.json").read_text())
        self.assertEqual(eh.get("schema"), "bugbountyci.engine_health.v1")
        # observations schema
        for o in _load_obs(rd):
            self.assertEqual(o.get("schema"), "bugbountyci.observation.v1")

    def test_99_report_metrics(self):
        m = self.metrics
        print("\n=== BENCHMARK METRICS (controlled fixtures only) ===")
        print(f"positives: {m['positives_detected']}/{m['positives_expected']} detected; missed={m['positives_missed']}")
        print(f"hard_neg correct: {m['hard_neg_correct']}/{m['hard_neg_expected_reject']}; promoted={m['hard_neg_incorrect_promoted']}")
        print(f"failure cases ok: {m['failure_cases_ok']}; fail={m['failure_cases_fail']}")
        print(f"schema ok/fail: {m['schema_ok']}/{m['schema_fail']}")
        print(f"provenance ok/fail: {m['provenance_ok']}/{m['provenance_fail']}")
        print(f"hunter delivery ok/fail: {m['hunter_delivery_ok']}/{m['hunter_delivery_fail']}")
        print(f"CONFIRMED violations: {m['confirmed_forbidden_violations']}")
        # Hard negatives incorrectly promoted is a known integration gap to fix
        if m["hard_neg_incorrect_promoted"]:
            print("GAP: hard negatives promoted as observations:", m["hard_neg_incorrect_promoted"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
