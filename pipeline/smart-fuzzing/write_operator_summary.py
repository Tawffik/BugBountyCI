#!/usr/bin/env python3
"""Roll up smart-fuzzing health for GATE / Easy-Wins (Intigriti-style honesty)."""
from __future__ import annotations

import json
import os
import sys


def _load(path):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return None


def _count_lines(path):
    if not os.path.isfile(path):
        return 0
    n = 0
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                n += 1
    return n


def main():
    if len(sys.argv) < 2:
        print("usage: write_operator_summary.py <results-dir>", file=sys.stderr)
        return 1
    rd = sys.argv[1]
    sf = os.path.join(rd, "smart-fuzzing")
    profile = _load(os.path.join(sf, "target_profile.json")) or {}
    wolf = _load(os.path.join(sf, "wolf_status.json")) or {}
    phase = _load(os.path.join(rd, "meta", "phases", "smart_fuzzing.json")) or {}
    outcome = _load(os.path.join(sf, "strategy_outcome.json")) or {}
    summary = {
        "schema": "bugbountyci.smart_fuzzing_operator_summary.v1",
        "hosts_count": profile.get("host_count"),
        "hosts_source": profile.get("hosts_source"),
        "wordlist_n": _count_lines(os.path.join(sf, "target_wordlist.txt")),
        "wolf_status": wolf.get("status") or ("OK" if _count_lines(os.path.join(sf, "wolf_selected.txt")) else "UNKNOWN"),
        "wolf_lines": wolf.get("selected_lines")
        if wolf.get("selected_lines") is not None
        else _count_lines(os.path.join(sf, "wolf_selected.txt")),
        "interesting_n": _count_lines(os.path.join(sf, "interesting.txt")),
        "pipeline_state": outcome.get("pipeline_state") or phase.get("detail"),
        "phase_status": phase.get("status"),
        "body_samples": (_load(os.path.join(sf, "body_samples_summary.json")) or {}).get("sampled"),
        "fallback_used": bool((_load(os.path.join(sf, "fallback_status.json")) or {}).get("used")),
        "note": "Intigriti-aligned rollup: custom wordlist health, not vulnerability claims.",
    }
    os.makedirs(sf, exist_ok=True)
    path = os.path.join(sf, "operator_summary.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
