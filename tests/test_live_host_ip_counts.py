"""live_hostname_urls vs live_ip_urls in target_profile (#162 honesty)."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path


def _load_mod():
    path = Path("scripts/write_pipeline_exports.py")
    spec = importlib.util.spec_from_file_location("write_pipeline_exports", path)
    mod = importlib.util.module_from_spec(spec)
    # Don't execute main - just compile presence
    return path.read_text(encoding="utf-8")


def test_export_script_defines_live_kind_counts():
    src = _load_mod()
    assert "live_hostname_urls" in src
    assert "live_ip_urls" in src
    assert "_count_live_kind" in src
    assert "ip_port_candidates" in src
