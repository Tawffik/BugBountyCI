#!/usr/bin/env python3
"""V2 response ranking offline benchmarks."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pipeline" / "smart-fuzzing"))
from response_diff import classify

def test_auth_redirect_server_waf():
    base = {"status": 200, "length": 1000, "content_type": "text/html"}
    assert classify({"status": 401, "length": 50}, base, False)[0] == "AUTH_REQUIRED"
    assert classify({"status": 302, "length": 20, "location": "/login"}, base, False)[0] == "REDIRECT"
    assert classify({"status": 500, "length": 100}, base, False)[0] == "SERVER_ERROR"
    assert classify({"status": 403, "length": 200}, base, False)[0] == "WAF_BLOCK"
    assert classify({"status": 200, "length": 8000, "content_type": "text/html"}, base, False)[0] == "INTERESTING"
    assert classify({"status": 200, "length": 1000, "content_type": "text/html"}, base, False)[0] == "NOISE"
    assert classify({"status": 200, "length": 1000}, None, False)[0] == "UNKNOWN"
    # no false WAF when baseline already blocked
    assert classify({"status": 403, "length": 200}, {"status": 403, "length": 200, "content_type": "text/html"}, False)[0] != "WAF_BLOCK"
    print("  OK V2 ranking classes")

if __name__ == "__main__":
    test_auth_redirect_server_waf()
    print("1/1 passed")
