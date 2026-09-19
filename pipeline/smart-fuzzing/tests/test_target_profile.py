#!/usr/bin/env python3
"""
tests/test_target_profile.py — regression test for the NDJSON parsing bug.

live/tech.json is NDJSON (one JSON object per line, one per host) - the
same format the pipeline's own jq calls assume. A plain json.load() on
this file throws on anything but a single line and was being silently
swallowed, so target_profile.py always reported zero technologies
regardless of what httpx actually found (confirmed on a real superdrug.com
run, compounded by a separate missing -td flag bug fixed in
scripts/live_host_probing.sh).
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SMART_FUZZING_DIR = os.path.dirname(HERE)
SCRIPT = os.path.join(SMART_FUZZING_DIR, "target_profile.py")


def test_ndjson_tech_detection():
    with tempfile.TemporaryDirectory() as tmp:
        live_dir = os.path.join(tmp, "live")
        os.makedirs(live_dir, exist_ok=True)
        # Real httpx -json -td output shape: one JSON object per line.
        with open(os.path.join(live_dir, "tech.json"), "w") as f:
            f.write(json.dumps({"url": "https://www.example.com", "status_code": 200,
                                 "tech": ["Next.js", "Node.js", "Cloudflare"]}) + "\n")
            f.write(json.dumps({"url": "https://api.example.com", "status_code": 404,
                                 "tech": ["Node.js"]}) + "\n")

        subprocess.run(
            [sys.executable, SCRIPT, "--results-dir", tmp, "--target", "example.com"],
            check=True, capture_output=True, text=True,
        )
        with open(os.path.join(tmp, "smart-fuzzing", "target_profile.json")) as f:
            profile = json.load(f)

        assert set(profile["technologies"]) == {"Next.js", "Node.js", "Cloudflare"}, (
            f"expected 3 technologies from NDJSON tech.json, got {profile['technologies']} "
            f"(NDJSON parsing regression?)"
        )
        print(f"  ✅ NDJSON tech.json parsed correctly: {profile['technologies']}")


def test_single_json_object_still_works():
    """Not every producer necessarily writes NDJSON — a plain single JSON
    object (or a JSON array) should still parse, since read_ndjson()
    falls through to per-line json.loads() which handles a single-line
    file too."""
    with tempfile.TemporaryDirectory() as tmp:
        live_dir = os.path.join(tmp, "live")
        os.makedirs(live_dir, exist_ok=True)
        with open(os.path.join(live_dir, "tech.json"), "w") as f:
            f.write(json.dumps({"url": "https://example.com", "tech": ["WordPress"]}))

        subprocess.run(
            [sys.executable, SCRIPT, "--results-dir", tmp, "--target", "example.com"],
            check=True, capture_output=True, text=True,
        )
        with open(os.path.join(tmp, "smart-fuzzing", "target_profile.json")) as f:
            profile = json.load(f)
        assert profile["technologies"] == ["WordPress"]
        print("  ✅ single-JSON-object tech.json still works")


def test_missing_tech_json_degrades_gracefully():
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [sys.executable, SCRIPT, "--results-dir", tmp, "--target", "example.com"],
            check=True, capture_output=True, text=True,
        )
        with open(os.path.join(tmp, "smart-fuzzing", "target_profile.json")) as f:
            profile = json.load(f)
        assert profile["technologies"] == []
        print("  ✅ missing tech.json degrades to empty list, no crash")


if __name__ == "__main__":
    tests = [test_ndjson_tech_detection, test_single_json_object_still_works,
              test_missing_tech_json_degrades_gracefully]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  ❌ {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
