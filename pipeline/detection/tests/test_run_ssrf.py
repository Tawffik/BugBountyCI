#!/usr/bin/env python3
"""
pipeline/detection/tests/test_run_ssrf.py
"""
import os
import sys
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, REPO_ROOT)

from pipeline.detection.run_ssrf import make_prober


def test_parses_status_and_body_from_real_curl_output_shape():
    """curl -o - -w '\n__STATUS__:%{http_code}' produces the body, then
    the status marker on the last line - confirms the parser splits
    that correctly and doesn't include the marker in the body."""
    curl_output = "some response body content\n__STATUS__:200"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = type("R", (), {"stdout": curl_output})()
        prober = make_prober("UA", use_tor=False, timeout=5)
        result = prober("https://example.com/?url=x")

    assert result["status"] == 200
    assert result["body"] == "some response body content"
    assert "elapsed_ms" in result
    print("  ✅ real curl body+status marker shape parsed correctly")


def test_body_is_capped_not_unbounded():
    huge_body = "A" * 50000
    curl_output = f"{huge_body}\n__STATUS__:200"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = type("R", (), {"stdout": curl_output})()
        prober = make_prober("UA", use_tor=False, timeout=5)
        result = prober("https://example.com/")
    assert len(result["body"]) <= 20000, "unbounded body storage — same class of bug as the 58,932-word vocabulary.json"
    print("  ✅ response body capped, not stored unbounded")


def test_direct_first_same_as_access_control_and_open_redirect():
    calls = []

    def spy_run(cmd, **kwargs):
        calls.append("tor" if cmd[0] == "proxychains4" else "direct")
        return type("R", (), {"stdout": "body\n__STATUS__:200"})()

    with patch("subprocess.run", side_effect=spy_run):
        prober = make_prober("UA", use_tor=True, timeout=5)
        prober("https://example.com/")

    assert calls == ["direct"], f"expected DIRECT only (no Tor needed), got {calls}"
    print("  ✅ DIRECT tried first, Tor not invoked when DIRECT succeeds")


def test_tor_fallback_when_direct_empty():
    calls = []

    def spy_run(cmd, **kwargs):
        is_tor = cmd[0] == "proxychains4"
        calls.append("tor" if is_tor else "direct")
        if is_tor:
            return type("R", (), {"stdout": "body\n__STATUS__:200"})()
        return type("R", (), {"stdout": ""})()  # DIRECT fails

    with patch("subprocess.run", side_effect=spy_run):
        prober = make_prober("UA", use_tor=True, timeout=5)
        result = prober("https://example.com/")

    assert calls == ["direct", "tor"]
    assert result["status"] == 200
    print("  ✅ Tor fallback used only when DIRECT returns nothing")


def test_malformed_output_returns_none():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = type("R", (), {"stdout": ""})()
        prober = make_prober("UA", use_tor=False, timeout=5)
        result = prober("https://example.com/")
    assert result is None
    print("  ✅ empty/malformed curl output returns None, not a crash")


if __name__ == "__main__":
    tests = [
        test_parses_status_and_body_from_real_curl_output_shape,
        test_body_is_capped_not_unbounded,
        test_direct_first_same_as_access_control_and_open_redirect,
        test_tor_fallback_when_direct_empty,
        test_malformed_output_returns_none,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  ❌ {t.__name__}: {e}")
        except Exception as e:
            failed += 1
            print(f"  ❌ {t.__name__}: unexpected {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
