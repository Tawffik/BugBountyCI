#!/usr/bin/env python3
"""
pipeline/detection/tests/test_run_open_redirect.py
"""
import os
import sys
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, REPO_ROOT)

from pipeline.detection.run_open_redirect import make_prober


def test_parses_status_and_location_from_real_curl_output_shape():
    """curl -D - -o /dev/null -w '\n%{http_code}' produces headers, then
    a blank line, then the status code on its own line - this confirms
    the parser reads that shape correctly."""
    curl_output = (
        "HTTP/1.1 302 Found\r\n"
        "Location: https://evil.example/\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
        "302"
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = type("R", (), {"stdout": curl_output})()
        prober = make_prober("UA", use_tor=False, timeout=5)
        result = prober("https://example.com/?redirect=x")

    assert result == {"status": 302, "location": "https://evil.example/"}
    print("  ✅ real curl -D - output shape parsed correctly (status + Location)")


def test_no_location_header_returns_empty_string_not_crash():
    curl_output = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n200"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = type("R", (), {"stdout": curl_output})()
        prober = make_prober("UA", use_tor=False, timeout=5)
        result = prober("https://example.com/")

    assert result == {"status": 200, "location": ""}
    print("  ✅ missing Location header handled gracefully (empty string, no crash)")


def test_direct_first_same_as_access_control():
    """Reuses the same DIRECT-first discipline established (and fixed)
    in run_access_control.py - confirming it wasn't forgotten here."""
    calls = []
    def spy_run(cmd, **kwargs):
        calls.append("tor" if cmd[0] == "proxychains4" else "direct")
        return type("R", (), {"stdout": "HTTP/1.1 200 OK\r\n\r\n200"})()

    with patch("subprocess.run", side_effect=spy_run):
        prober = make_prober("UA", use_tor=True, timeout=5)
        prober("https://example.com/")

    assert calls == ["direct"], f"expected DIRECT only (no Tor needed), got {calls}"
    print("  ✅ DIRECT tried first, Tor not invoked when DIRECT succeeds (consistent with access-control fix)")


def test_malformed_output_returns_none():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = type("R", (), {"stdout": ""})()
        prober = make_prober("UA", use_tor=False, timeout=5)
        result = prober("https://example.com/")
    assert result is None
    print("  ✅ empty/malformed curl output returns None, not a crash")


if __name__ == "__main__":
    tests = [
        test_parses_status_and_location_from_real_curl_output_shape,
        test_no_location_header_returns_empty_string_not_crash,
        test_direct_first_same_as_access_control,
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
