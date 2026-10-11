#!/usr/bin/env python3
import json, os, tempfile, unittest, io, contextlib, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from record_info_disclosure_probe import build_record, append_record, redact, main

class TestRecordProbe(unittest.TestCase):
    def test_redact_password_line(self):
        t = "API_KEY=supersecretvalue123\nOTHER=ok\n"
        r = redact(t)
        self.assertNotIn("supersecretvalue123", r)
        self.assertIn("REDACTED", r)

    def test_build_truncation(self):
        td = tempfile.mkdtemp()
        bf = os.path.join(td, "b.txt")
        open(bf, "w").write("A" * 5000)
        rec = build_record("https://x/.env", "/.env", 200, body_file=bf)
        self.assertTrue(rec["body_truncated"])
        self.assertLessEqual(len(rec["body"]), 2048)

    def test_append_dedupe(self):
        td = tempfile.mkdtemp()
        out = os.path.join(td, "probe_results.jsonl")
        bf = os.path.join(td, "b.txt")
        open(bf, "w").write("ref: refs/heads/main\n")
        rec = build_record("https://x/.git/HEAD", "/.git/HEAD", 200, body_file=bf)
        append_record(out, rec)
        append_record(out, rec)
        self.assertEqual(len([l for l in open(out) if l.strip()]), 1)

    def test_empty_body_file(self):
        rec = build_record("https://x/.env", "/.env", 200, body_file=None)
        self.assertEqual(rec["body_len"], 0)

    def test_init_only(self):
        td = tempfile.mkdtemp()
        out = os.path.join(td, "probe_results.jsonl")
        self.assertEqual(main(["--out", out, "--init-only"]), 0)
        self.assertTrue(os.path.isfile(out))

    def test_no_secret_in_stdout_or_file(self):
        td = tempfile.mkdtemp()
        out = os.path.join(td, "probe_results.jsonl")
        bf = os.path.join(td, "b.txt")
        open(bf, "w").write("API_KEY=supersecretvalue999\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["--out", out, "--url", "https://x/.env", "--path", "/.env", "--status", "200", "--body-file", bf])
        self.assertNotIn("supersecretvalue999", buf.getvalue())
        self.assertNotIn("supersecretvalue999", open(out).read())
        self.assertIn("REDACTED", open(out).read())

if __name__ == "__main__":
    unittest.main(verbosity=2)
