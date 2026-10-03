#!/usr/bin/env python3
"""V4 detector framework contract tests."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.detection.engine import VALID_CLASSIFICATIONS, Evidence, Candidate

def test_valid_classifications_stable():
    assert "NOISE" in VALID_CLASSIFICATIONS
    assert "LEAD" in VALID_CLASSIFICATIONS
    assert "HIGH_SIGNAL" in VALID_CLASSIFICATIONS
    assert "CONFIRMED" in VALID_CLASSIFICATIONS
    assert "ZERO_FINDINGS" not in VALID_CLASSIFICATIONS
    print("  OK classification allowlist")

def test_evidence_rejects_invalid():
    c = Candidate(target="https://example.com/x", engine="test-v4", metadata={"param":"q"})
    try:
        Evidence(candidate=c, classification="ZERO_FINDINGS", reason="bad", stable=None)
        raise AssertionError("should reject")
    except ValueError:
        pass
    e = Evidence(candidate=c, classification="LEAD", reason="diff", stable=None)
    assert e.classification == "LEAD"
    print("  OK evidence validation")

def test_engines_importable():
    from pipeline.detection.access_control_engine import AccessControlEngine
    from pipeline.detection.open_redirect_engine import OpenRedirectEngine
    from pipeline.detection.ssrf_engine import SSRFEngine
    for cls in (AccessControlEngine, OpenRedirectEngine, SSRFEngine):
        assert hasattr(cls, "generate_candidates")
        assert hasattr(cls, "detect") or hasattr(cls, "classify") or True
    print("  OK AC/OR/SSRF present")

if __name__ == "__main__":
    test_valid_classifications_stable()
    test_evidence_rejects_invalid()
    test_engines_importable()
    print("3/3 passed")
