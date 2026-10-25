#!/usr/bin/env python3
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pipeline.detection.hunter_queue_builder import demote_unconfirmed_ssrf


def test_demote_ssrf_high_without_oob():
    e = demote_unconfirmed_ssrf({
        "engine": "ssrf-v1",
        "classification": "HIGH_SIGNAL",
        "reason": "differential stable",
    })
    assert e["classification"] == "LEAD"
    assert e["priority_class"] == "LEAD"


def test_keep_ssrf_high_with_oob():
    e = demote_unconfirmed_ssrf({
        "engine": "ssrf-v1",
        "classification": "HIGH_SIGNAL",
        "reason": "differential; OOB_CONFIRMED label=abc",
        "oob_confirmed": True,
    })
    assert e["classification"] == "HIGH_SIGNAL"


if __name__ == "__main__":
    test_demote_ssrf_high_without_oob()
    test_keep_ssrf_high_with_oob()
    print("ok")
