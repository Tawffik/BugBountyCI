#!/usr/bin/env python3
"""
tests/test_vocabulary.py — regression test for the hash-noise bug.

On a real run (superdrug.com), vocabulary.json reached 4MB / ~59k words,
99.7% of them asset/cache-busting hashes like
"ca19626ec727b5901735ca91a33b36" mistaken for application vocabulary.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SMART_FUZZING_DIR = os.path.dirname(HERE)
SCRIPT = os.path.join(SMART_FUZZING_DIR, "vocabulary.py")


def test_hex_hashes_are_filtered():
    with tempfile.TemporaryDirectory() as tmp:
        js_deep = os.path.join(tmp, "js_deep")
        os.makedirs(js_deep, exist_ok=True)
        with open(os.path.join(js_deep, "linkfinder_endpoints.txt"), "w") as f:
            f.write("/static/ca19626ec727b5901735ca91a33b36.js\n")
            f.write("/api/invoices\n")
            f.write("/static/v2ab34f109cc881.css\n")

        subprocess.run(
            [sys.executable, SCRIPT, "--results-dir", tmp, "--target", "example.com"],
            check=True, capture_output=True, text=True,
        )
        with open(os.path.join(tmp, "smart-fuzzing", "vocabulary.json")) as f:
            vocab = json.load(f)

        assert "ca19626ec727b5901735ca91a33b36" not in vocab, "raw hex hash leaked into vocabulary"
        assert "v2ab34f109cc881" not in vocab, "mixed hash/version string leaked into vocabulary"
        assert "invoices" in vocab, "real vocabulary word was wrongly filtered"
        print(f"  ✅ hex/hash noise filtered, real word 'invoices' kept ({len(vocab)} total words)")


def test_output_is_bounded():
    """Even if a future noise source slips past the hash filter, the
    output must stay bounded (MAX_VOCAB_SIZE safety net)."""
    with tempfile.TemporaryDirectory() as tmp:
        urls_dir = os.path.join(tmp, "urls")
        os.makedirs(urls_dir, exist_ok=True)
        with open(os.path.join(urls_dir, "all.txt"), "w") as f:
            # 5000 distinct short alphabetic "words" - not hash-like, so the
            # hash filter won't catch them, but the cap must still bound output.
            for i in range(5000):
                f.write(f"/path/wordxyz{i:04d}abc\n")

        subprocess.run(
            [sys.executable, SCRIPT, "--results-dir", tmp, "--target", "example.com"],
            check=True, capture_output=True, text=True,
        )
        with open(os.path.join(tmp, "smart-fuzzing", "vocabulary.json")) as f:
            vocab = json.load(f)
        assert len(vocab) <= 2000, f"expected output capped at 2000, got {len(vocab)}"
        print(f"  ✅ output bounded at {len(vocab)} words even with 5000 unique inputs")


if __name__ == "__main__":
    tests = [test_hex_hashes_are_filtered, test_output_is_bounded]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  ❌ {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
