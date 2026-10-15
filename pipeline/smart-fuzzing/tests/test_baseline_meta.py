"""baseline.py must record truncation in baseline_meta.json."""
from pathlib import Path


def test_baseline_writes_meta_schema():
    src = (Path(__file__).resolve().parents[1] / "baseline.py").read_text(encoding="utf-8")
    assert "baseline_meta.json" in src
    assert "hosts_truncated" in src
    assert "bugbountyci.baseline_meta.v1" in src
