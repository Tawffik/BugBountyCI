"""Ensure critical Zero Track phase order stays correct."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WF = (ROOT / ".github/workflows/zero-track-hunter.yml").read_text(encoding="utf-8")


def names():
    return re.findall(r'^\s{6}- name: "([^"]+)"', WF, re.M)


class WorkflowPhaseOrder(unittest.TestCase):
    def test_param_intel_after_fuzz_before_access(self):
        n = names()
        api = next(i for i, x in enumerate(n) if "API Discovery" in x)
        fuzz = next(i for i, x in enumerate(n) if "Content Discovery Fuzzing" in x)
        pi = next(i for i, x in enumerate(n) if "Parameter Intelligence" in x)
        ac = next(i for i, x in enumerate(n) if "Access-Control" in x)
        oob = next(i for i, x in enumerate(n) if "OOB Setup" in x)
        ssrf = next(i for i, x in enumerate(n) if "SSRF Intelligence" in x)
        self.assertLess(api, fuzz)
        self.assertLess(fuzz, pi)
        self.assertLess(pi, ac)
        self.assertLess(oob, ssrf)

    def test_step_count_stable(self):
        # Guard against accidental step drop during reorder
        self.assertGreaterEqual(len(names()), 70)


if __name__ == "__main__":
    unittest.main()
