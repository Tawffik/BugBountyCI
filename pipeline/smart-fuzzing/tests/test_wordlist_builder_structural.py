import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCRIPT = os.path.join(REPO_ROOT, "pipeline", "smart-fuzzing", "wordlist_builder.py")


class TestWordlistBuilderStructuralSource(unittest.TestCase):
    """Wired-in real, not mocked: this actually runs wordlist_builder.py
    as a subprocess (same as the workflow does) against a results-dir
    layout that mirrors a real run, to prove the new predicted_paths.json
    source is genuinely consumed end-to-end, not just importable."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.rd = self.tmp
        os.makedirs(os.path.join(self.rd, "smart-fuzzing"), exist_ok=True)
        os.makedirs(os.path.join(self.rd, "detection"), exist_ok=True)

        with open(os.path.join(self.rd, "smart-fuzzing", "wolf_selected.txt"), "w") as f:
            f.write("backup\nconfig.php\n")

        vocab = {
            "invoice": {"count": 5, "sources": ["js"]},
            "export": {"count": 2, "sources": ["js"]},
        }
        with open(os.path.join(self.rd, "smart-fuzzing", "vocabulary.json"), "w") as f:
            json.dump(vocab, f)

        predicted = [
            {
                "path": "/invoices/{id}/delivery",
                "evidence": {
                    "kind": "cross_resource_action",
                    "resource_seen_in": "https://x.com/invoices/701",
                    "action_seen_in": "https://x.com/orders/9/delivery",
                    "sample_id_used": "701",
                    "fuzz_path": "invoices/701/delivery",
                    "reason": "test fixture",
                },
            },
            {
                # No fuzz_path (no sample id was ever observed) — must
                # be skipped, ffuf cannot test a literal "{id}" token.
                "path": "/receipts/{id}/export",
                "evidence": {
                    "kind": "cross_resource_action",
                    "sample_id_used": "",
                    "fuzz_path": "",
                },
            },
        ]
        with open(os.path.join(self.rd, "detection", "predicted_paths.json"), "w") as f:
            json.dump(predicted, f)

    def _run(self, mode="normal"):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--results-dir", self.rd, "--mode", mode],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        out_path = os.path.join(self.rd, "smart-fuzzing", "target_wordlist.txt")
        with open(out_path) as f:
            return [l.strip() for l in f if l.strip()]

    def test_structural_fuzz_path_included(self):
        lines = self._run()
        self.assertIn("invoices/701/delivery", lines)

    def test_placeholder_only_prediction_excluded(self):
        # the second fixture entry has no real id — must never leak the
        # literal "{id}" token into a real ffuf wordlist
        lines = self._run()
        for l in lines:
            self.assertNotIn("{id}", l)

    def test_existing_sources_still_present(self):
        lines = self._run()
        self.assertIn("backup", lines)
        self.assertIn("invoice", lines)

    def test_missing_predicted_paths_file_does_not_crash(self):
        os.remove(os.path.join(self.rd, "detection", "predicted_paths.json"))
        lines = self._run()  # must not raise
        self.assertIn("backup", lines)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestWordlistBuilderSourceBalance(unittest.TestCase):
    """Real bug found reviewing a live superdrug.com run's actual
    target_wordlist.txt: Wolf contributed 220/300 (73%) of the final
    wordlist while vocabulary.json (this target's OWN evidence)
    contributed only 5/2000 available words (0.25%) - Wolf's ~4000
    unfiltered entries were added to the candidate set uncapped, and
    ranked ahead of vocabulary words. This class proves each source now
    gets a real, capped, non-zero share regardless of how many
    candidates the others produce."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.rd = self.tmp
        os.makedirs(os.path.join(self.rd, "smart-fuzzing"), exist_ok=True)
        os.makedirs(os.path.join(self.rd, "detection"), exist_ok=True)

        # Simulate the real-world shape: Wolf massively outnumbers
        # vocabulary (4000 vs a few dozen), same as the actual run that
        # exposed this bug.
        wolf_words = [f"generic-tool-name-{i}" for i in range(4000)]
        with open(os.path.join(self.rd, "smart-fuzzing", "wolf_selected.txt"), "w") as f:
            f.write("\n".join(wolf_words) + "\n")

        vocab = {f"realword{i}": {"count": 10 - (i % 5), "sources": ["js"]} for i in range(30)}
        with open(os.path.join(self.rd, "smart-fuzzing", "vocabulary.json"), "w") as f:
            json.dump(vocab, f)

        with open(os.path.join(self.rd, "detection", "predicted_paths.json"), "w") as f:
            json.dump([], f)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, mode="normal"):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--results-dir", self.rd, "--mode", mode],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(os.path.join(self.rd, "smart-fuzzing", "target_wordlist.txt")) as f:
            return [l.strip() for l in f if l.strip()]

    def test_wolf_does_not_dominate_the_final_wordlist(self):
        lines = self._run()
        wolf_lines_in_final = sum(1 for l in lines if l.startswith("generic-tool-name-"))
        # Wolf must be capped, not allowed to fill the whole 300-line
        # budget just because it has 4000 candidates available.
        self.assertLess(wolf_lines_in_final, 150,
                         "Wolf crowded out other sources again - this is the exact bug being regression-tested")

    def test_vocabulary_words_are_not_starved(self):
        lines = self._run()
        vocab_lines_in_final = sum(1 for l in lines if l.startswith("realword"))
        # All 30 real vocabulary words (well under any reasonable cap)
        # must make it in given they're this target's own evidence -
        # not get reduced to a token few percent by Wolf's sheer volume.
        self.assertGreaterEqual(vocab_lines_in_final, 20,
                                 "vocabulary.json words starved by Wolf's generic pool - the exact bug being regression-tested")

    def test_every_source_gets_a_real_share(self):
        # None of the three sources should end up at zero just because
        # another source had more raw candidates available.
        lines = self._run()
        wolf_n = sum(1 for l in lines if l.startswith("generic-tool-name-"))
        vocab_n = sum(1 for l in lines if l.startswith("realword"))
        self.assertGreater(wolf_n, 0)
        self.assertGreater(vocab_n, 0)


if __name__ == "__main__":
    unittest.main()
