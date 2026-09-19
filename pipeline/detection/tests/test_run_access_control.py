#!/usr/bin/env python3
"""
pipeline/detection/tests/test_run_access_control.py

Tests make_prober()'s DIRECT-first-with-Tor-fallback priority — the fix
for the bug where a WAF treating Tor exit nodes differently could mask a
real bypass or fabricate a fake one, because the original version tried
Tor first and only fell back to DIRECT when Tor returned literally
nothing (not when it returned a different-but-valid status).

Uses a mocked subprocess.run instead of a real server so this is fast
and has no background-process/networking flakiness.
"""
import os
import sys
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, REPO_ROOT)

from pipeline.detection.run_access_control import make_prober


def _fake_run(direct_response, tor_response):
    """Returns a fake subprocess.run() that inspects the command to
    decide whether this is the DIRECT call or the proxychains4/Tor call,
    and returns the matching canned response."""
    class FakeResult:
        def __init__(self, stdout):
            self.stdout = stdout

    def fake_run(cmd, **kwargs):
        is_tor = cmd[0] == "proxychains4"
        resp = tor_response if is_tor else direct_response
        if resp is None:
            return FakeResult(stdout="")  # simulates total failure / no output
        body, status, ctype = resp
        return FakeResult(stdout=f"{body}\n{status}\n{ctype}")
    return fake_run


def test_direct_is_tried_first_and_used_when_it_succeeds():
    """The core fix: even with use_tor=True, DIRECT must be the one
    actually used when it succeeds — Tor is not even consulted."""
    calls = []
    def spy_run(cmd, **kwargs):
        calls.append(cmd[0] if cmd[0] != "curl" else "curl-direct")
        if cmd and cmd[0] == "proxychains4":
            calls[-1] = "curl-via-tor"
        return type("R", (), {"stdout": "body-direct\n200\ntext/html"})()

    with patch("subprocess.run", side_effect=spy_run):
        prober = make_prober("UA", use_tor=True, timeout=5)
        result = prober("https://example.com/admin")

    assert result == {"status": 200, "length": len("body-direct"), "content_type": "text/html"}
    assert "curl-via-tor" not in calls, "Tor should never be called when DIRECT already succeeded"
    print("  ✅ DIRECT succeeds -> used directly, Tor never even attempted")


def test_falls_back_to_tor_only_when_direct_totally_fails():
    fake_run = _fake_run(direct_response=None, tor_response=("body-tor", "403", "text/html"))
    with patch("subprocess.run", side_effect=fake_run):
        prober = make_prober("UA", use_tor=True, timeout=5)
        result = prober("https://example.com/admin")

    assert result == {"status": 403, "length": len("body-tor"), "content_type": "text/html"}
    print("  ✅ DIRECT total failure -> falls back to Tor as last resort")


def test_direct_disagreeing_status_still_wins_over_tor():
    """This is exactly the bug scenario: Tor would give a DIFFERENT
    (but valid) status than DIRECT, e.g. a WAF Tor-block page. The fix
    means DIRECT's answer is what gets used, not Tor's, since DIRECT
    didn't fail outright."""
    fake_run = _fake_run(
        direct_response=("real-admin-page-content", "200", "application/json"),
        tor_response=("tor-block-page", "403", "text/html"),
    )
    with patch("subprocess.run", side_effect=fake_run):
        prober = make_prober("UA", use_tor=True, timeout=5)
        result = prober("https://example.com/admin/")

    assert result["status"] == 200, (
        "DIRECT's real 200 must be used, not Tor's unrelated 403 block page "
        "(this was the exact false-negative bug scenario)"
    )
    print("  ✅ DIRECT's answer wins even when Tor would have given a different status "
          "(prevents both false negatives and false positives from Tor/WAF interaction)")


def test_no_tor_flag_never_calls_proxychains():
    calls = []
    def spy_run(cmd, **kwargs):
        calls.append(cmd[0])
        return type("R", (), {"stdout": "body\n200\ntext/html"})()

    with patch("subprocess.run", side_effect=spy_run):
        prober = make_prober("UA", use_tor=False, timeout=5)
        prober("https://example.com/admin")

    assert "proxychains4" not in calls
    print("  ✅ use_tor=False never invokes proxychains4, even as a fallback")


if __name__ == "__main__":
    tests = [
        test_direct_is_tried_first_and_used_when_it_succeeds,
        test_falls_back_to_tor_only_when_direct_totally_fails,
        test_direct_disagreeing_status_still_wins_over_tor,
        test_no_tor_flag_never_calls_proxychains,
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
