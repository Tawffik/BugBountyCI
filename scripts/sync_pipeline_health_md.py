#!/usr/bin/env python3
"""Rewrite pipeline_health.md Overall from engine_health.overall.

pipeline_health.md is written before write_pipeline_exports.py computes the
authoritative overall. Without this sync, MD can stay HEALTHY while
engine_health.overall is DEGRADED (observed on Zero Track #167).

Does not change SI→Hunter, caps, or scanner inventory.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

LABEL = {
    "OK": "\U0001f7e2 HEALTHY",
    "DEGRADED": "\U0001f7e1 DEGRADED \u2014 see engine_health / flags",
    "BROKEN": "\U0001f534 BROKEN \u2014 critical stage failure",
    "PARTIAL": "\U0001f7e1 PARTIAL",
}


def sync(results_dir: str) -> int:
    rd = Path(results_dir)
    eh_path = rd / "meta" / "engine_health.json"
    md_path = rd / "meta" / "pipeline_health.md"
    if not eh_path.is_file() or not md_path.is_file():
        print("[health-sync] skip: missing engine_health or pipeline_health.md")
        return 0
    try:
        eh = json.loads(eh_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"[health-sync] skip: bad engine_health: {e}")
        return 0
    overall = str(eh.get("overall") or "OK")
    label = LABEL.get(overall, overall)
    md = md_path.read_text(encoding="utf-8", errors="replace")
    md2, n = re.subn(r"(## Overall:\s*).*", r"\1" + label, md, count=1)
    if not n:
        print("[health-sync] no Overall line found")
        return 0
    md_path.write_text(md2, encoding="utf-8")
    print(f"[health-sync] Overall \u2192 {label} (engine_health.overall={overall})")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sync_pipeline_health_md.py <results_dir>", file=sys.stderr)
        return 2
    return sync(sys.argv[1])


if __name__ == "__main__":
    raise SystemExit(main())
