#!/usr/bin/env python3
"""Historical pivot must not treat path-on-other-host as STILL_LIVE."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "historical_404_pivot.py"


def test_cross_host_path_is_not_still_live(tmp_path):
    rd = tmp_path / "results"
    (rd / "urls").mkdir(parents=True)
    (rd / "meta").mkdir(parents=True)
    (rd / "meta" / "target_profile.json").write_text('{"target": "example.com"}\n')
    # current surface only on www
    (rd / "urls" / "all.txt").write_text("https://www.example.com/admin\n")
    # historical path same but different host still under target
    (rd / "urls" / "wayback.txt").write_text(
        "https://api.example.com/admin\n"
        "https://evil.com/admin\n"
        "https://www.example.com/admin\n"
    )
    (rd / "urls" / "gau.txt").write_text("")
    subprocess.check_call([sys.executable, str(SCRIPT), "--results-dir", str(rd), "--target", "example.com"])
    rows = [json.loads(l) for l in open(rd / "info_disclosure" / "historical_pivots.jsonl") if l.strip()]
    by_url = {r["url"]: r for r in rows}
    # www same host+path → STILL_LIVE
    assert by_url["https://www.example.com/admin"]["classification"] == "STILL_LIVE"
    # api same apex different host, path not on api → HISTORICAL_PATH_CURRENT_HOST or ARCHIVE
    api = by_url.get("https://api.example.com/admin")
    assert api is not None
    assert api["classification"] != "STILL_LIVE" or api.get("current_path_match") is False
    # evil out of scope — should be dropped
    assert "https://evil.com/admin" not in by_url
    summary = json.load(open(rd / "info_disclosure" / "historical_pivot_summary.json"))
    assert summary.get("historical_dropped_out_of_scope", 0) >= 1
    print("OK cross-host path")


if __name__ == "__main__":
    import tempfile
    from pathlib import Path as P
    with tempfile.TemporaryDirectory() as d:
        test_cross_host_path_is_not_still_live(P(d))
