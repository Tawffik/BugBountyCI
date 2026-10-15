"""engine_health.overall must be a stable enum, not only an emoji string."""
from __future__ import annotations

from pathlib import Path


def test_write_pipeline_exports_normalizes_overall():
    src = Path("scripts/write_pipeline_exports.py").read_text(encoding="utf-8")
    assert "overall_status" in src
    assert "overall_display" in src
    assert '"overall": overall_status' in src
