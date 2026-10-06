#!/usr/bin/env python3
import json, os, sys, tempfile, unittest
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import normalize_linkfinder as m  # noqa: E402

class LinkFinderNormalizeTests(unittest.TestCase):
    def test_chunk_is_static(self):
        c, _, _ = m.classify_path("./chunk-ABC.js", {"example.com"})
        self.assertEqual(c, "STATIC_ASSET")
    def test_api_route(self):
        c, _, _ = m.classify_path("/api/users", {"example.com"})
        self.assertEqual(c, "API_ROUTE")
    def test_external(self):
        c, _, _ = m.classify_path("https://google.com/x", {"example.com"})
        self.assertEqual(c, "EXTERNAL")
    def test_raw_not_equal_api(self):
        td = tempfile.mkdtemp()
        os.makedirs(os.path.join(td, "js_deep"))
        with open(os.path.join(td, "js_deep", "linkfinder_endpoints.txt"), "w") as f:
            f.write("[a.js] ./chunk.js\n[a.js] /api/x\n")
        s = m.normalize_file(os.path.join(td, "js_deep", "linkfinder_endpoints.txt"), td, "example.com")
        self.assertEqual(s["raw_lines"], 2)
        self.assertEqual(s["api_routes"], 1)
        self.assertEqual(s["static_assets"], 1)

if __name__ == "__main__":
    unittest.main()
