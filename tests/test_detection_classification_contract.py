#!/usr/bin/env python3
"""V4: detection classification contract — allowed labels only."""
ALLOWED = {
    "NOISE", "LOW_SIGNAL", "LEAD", "HIGH_SIGNAL", "CONFIRMED",
    "INTERESTING", "AUTH_REQUIRED", "SERVER_ERROR", "REDIRECT",
    "WAF_BLOCK", "SPA_FALLBACK", "DUPLICATE", "UNKNOWN",
}

def test_response_diff_labels_are_in_contract():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pipeline" / "smart-fuzzing"))
    from response_diff import classify
    base = {"status": 200, "length": 1000, "content_type": "text/html"}
    samples = [
        {"status": 401, "length": 10},
        {"status": 302, "length": 10},
        {"status": 500, "length": 10},
        {"status": 403, "length": 10},
        {"status": 200, "length": 5000, "content_type": "text/html"},
        {"status": 200, "length": 1000, "content_type": "text/html"},
    ]
    for s in samples:
        label, _ = classify(s, base, False)
        assert label in ALLOWED, label
    label, _ = classify({"status": 200, "length": 1}, None, False)
    assert label in ALLOWED
    print("  OK classification contract")

if __name__ == "__main__":
    test_response_diff_labels_are_in_contract()
    print("1/1 passed")
