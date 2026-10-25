#!/usr/bin/env python3
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pipeline.detection.smart_403_engine import is_interesting, gen_techniques, _fingerprint


def test_fp_cloudflare():
    assert _fingerprint({"cf-ray": "abc"}, "cloudflare") == "cloudflare"


def test_interesting_status_change():
    base = {"status": 403, "length": 100, "body_hash": "aaa", "content_type": "text/html", "location": ""}
    cand = {"status": 200, "length": 500, "body_hash": "bbb", "content_type": "text/html", "location": ""}
    ok, reason = is_interesting(base, cand, None)
    assert ok and "status" in reason


def test_reject_identical_and_404_calib():
    base = {"status": 403, "length": 100, "body_hash": "aaa", "content_type": "text/html", "location": ""}
    same = dict(base)
    ok, _ = is_interesting(base, same, None)
    assert not ok
    calib = {"status": 404, "length": 120, "body_hash": "ccc"}
    cand = {"status": 404, "length": 125, "body_hash": "ccc", "content_type": "text/html", "location": ""}
    ok, reason = is_interesting(base, cand, calib)
    assert not ok


def test_reject_login_redirect():
    base = {"status": 403, "length": 100, "body_hash": "aaa", "content_type": "text/html", "location": ""}
    cand = {"status": 302, "length": 50, "body_hash": "zzz", "content_type": "text/html", "location": "https://x/login"}
    ok, reason = is_interesting(base, cand, None)
    assert not ok


def test_gen_techniques_capped():
    techs = gen_techniques("https://example.com/admin", "azure")
    assert len(techs) <= 28
    assert any(t[0] == "azure-query" for t in techs)


if __name__ == "__main__":
    test_fp_cloudflare()
    test_interesting_status_change()
    test_reject_identical_and_404_calib()
    test_reject_login_redirect()
    test_gen_techniques_capped()
    print("ok")
