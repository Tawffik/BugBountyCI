#!/usr/bin/env python3
"""Representation Differential candidate-selection contract tests."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import representation_differential as rd  # noqa: E402


class SelectCandidatesTests(unittest.TestCase):
    def _rd(self, endpoints=None, urls=None, live=None, target="target.example"):
        td = tempfile.mkdtemp()
        os.makedirs(os.path.join(td, "meta"), exist_ok=True)
        os.makedirs(os.path.join(td, "live"), exist_ok=True)
        os.makedirs(os.path.join(td, "urls"), exist_ok=True)
        if endpoints is not None:
            with open(os.path.join(td, "meta", "endpoints.jsonl"), "w") as f:
                for ep in endpoints:
                    f.write(json.dumps({"endpoint": ep}) + "\n")
        if live is not None:
            with open(os.path.join(td, "live", "live.txt"), "w") as f:
                for u in live:
                    f.write(u + "\n")
        if urls is not None:
            with open(os.path.join(td, "urls", "all.txt"), "w") as f:
                for u in urls:
                    f.write(u + "\n")
        return rd.select_candidates(td, cap=40, target=target)

    def test_relative_api_bound_to_target(self):
        c = self._rd(
            endpoints=["/api/profile"],
            live=["https://target.example"],
            target="target.example",
        )
        urls = {x["url"] for x in c}
        self.assertIn("https://target.example/api/profile", urls)
        self.assertTrue(any("hostbind" in x["reason_selected"] for x in c))

    def test_google_rejected(self):
        c = self._rd(
            endpoints=["https://google.com/api/x", "https://www.google.com/url"],
            live=["https://target.example"],
            target="target.example",
        )
        for x in c:
            self.assertNotIn("google.com", x["url"])

    def test_absolute_in_scope_api_accepted(self):
        c = self._rd(
            endpoints=["https://target.example/api/users"],
            live=["https://target.example"],
            target="target.example",
        )
        urls = {x["url"] for x in c}
        self.assertIn("https://target.example/api/users", urls)

    def test_external_evil_rejected(self):
        c = self._rd(
            endpoints=["https://evil.example/api/x"],
            live=["https://target.example"],
            target="target.example",
        )
        self.assertEqual(c, [])

    def test_api_host_root_accepted(self):
        c = self._rd(
            urls=["https://api.target.example/"],
            live=["https://api.target.example"],
            target="target.example",
        )
        urls = {x["url"] for x in c}
        self.assertTrue(any("api.target.example" in u for u in urls))

    def test_static_asset_rejected(self):
        c = self._rd(
            endpoints=["https://target.example/api/app.js"],
            live=["https://target.example"],
            target="target.example",
        )
        self.assertEqual(c, [])

    def test_budget_cap(self):
        eps = [f"https://target.example/api/r{i}" for i in range(50)]
        c = rd.select_candidates  # noqa
        td_eps = eps
        # use helper with cap via direct call
        import tempfile
        td = tempfile.mkdtemp()
        os.makedirs(os.path.join(td, "meta"), exist_ok=True)
        os.makedirs(os.path.join(td, "live"), exist_ok=True)
        with open(os.path.join(td, "meta", "endpoints.jsonl"), "w") as f:
            for ep in td_eps:
                f.write(json.dumps({"endpoint": ep}) + "\n")
        open(os.path.join(td, "live", "live.txt"), "w").write("https://target.example\n")
        c = rd.select_candidates(td, cap=10, target="target.example")
        self.assertLessEqual(len(c), 10)


if __name__ == "__main__":
    unittest.main()
