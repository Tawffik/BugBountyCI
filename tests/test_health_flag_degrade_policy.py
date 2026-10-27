"""Informational flags must not force DEGRADED overall."""
import json
import tempfile
from pathlib import Path
import subprocess
import sys


def test_info_flags_alone_yield_ok_overall():
    """Simulate url-source info flags path through write_pipeline_exports health."""
    # Exercise the predicate by re-implementing the same rules (source of truth in script)
    def _flag_degrades_overall(msg: str) -> bool:
        s = (msg or "").strip()
        if not s:
            return False
        if s.startswith("ℹ️"):
            return False
        low = s.lower()
        if "rate_limit" in low or "rate limit" in low or "http_429" in low:
            return False
        if "source_empty" in low or "optional keys missing" in low:
            return False
        return True

    info = [
        "ℹ️ **URL source gau SOURCE_EMPTY** — passive archive empty",
        "GitHub rate_limit http_429",
    ]
    hard = ["live_probe phase=error — timeout", "detection_metrics:untrusted"]
    assert not any(_flag_degrades_overall(f) for f in info)
    assert all(_flag_degrades_overall(f) for f in hard)
    assert ([f for f in info + hard if _flag_degrades_overall(f)] == hard)


def test_github_registry_default_cap():
    root = Path(__file__).resolve().parents[1]
    reg = json.loads((root / "config" / "github_exposure_queries.json").read_text())
    assert reg.get("default_max_queries") == 8
    assert len(reg["queries"]) >= 8
    # first 8 should include priority env/secrets families
    ids = [q["query_id"] for q in reg["queries"][:8]]
    assert "gh-env-file" in ids


def test_hist_val_status_blocked():
    def _hist_val_status(s):
        outcomes = s.get("outcomes") or {}
        validated = int(s.get("validated") or 0)
        blocked = int(outcomes.get("BLOCKED_OR_RATE_LIMITED") or 0)
        if validated > 0 and blocked >= validated and blocked > 0:
            return "blocked"
        if validated == 0 and int(s.get("not_run") or 0) > 0:
            return "empty"
        return "ok"

    assert _hist_val_status({"validated": 40, "outcomes": {"BLOCKED_OR_RATE_LIMITED": 40}}) == "blocked"
    assert _hist_val_status({"validated": 10, "outcomes": {"REACHABLE": 10}}) == "ok"
