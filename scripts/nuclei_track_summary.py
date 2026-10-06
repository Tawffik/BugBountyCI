#!/usr/bin/env python3
"""nuclei_track_summary.py — separate track status for Nuclei (not core recon intelligence).

Writes meta/nuclei_track.json with honest states:
  NOT_RUN | NO_INPUT | PARTIAL | DEGRADED | SUCCESS | EMPTY_VALID

Never maps high error rate + 0 findings to CLEAN.
"""
from __future__ import annotations

import argparse
import json
import os
import re


def load_json(path: str):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", errors="ignore") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def count_lines(path: str) -> int:
    if not os.path.isfile(path):
        return 0
    n = 0
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def parse_error_rate_from_health(rd: str) -> float | None:
    eh = load_json(os.path.join(rd, "meta", "engine_health.json"))
    if not eh:
        return None
    for flag in eh.get("flags") or []:
        m = re.search(r"error_rate=([0-9.]+)", str(flag))
        if m:
            return float(m.group(1))
        m = re.search(r"error rate is ([0-9.]+)%", str(flag), re.I)
        if m:
            return float(m.group(1))
    return None


def summarize(rd: str) -> dict:
    phase = load_json(os.path.join(rd, "meta", "phases", "nuclei.json")) or {}
    findings = count_lines(os.path.join(rd, "nuclei", "findings.jsonl"))
    err_rate = parse_error_rate_from_health(rd)
    status = str(phase.get("status") or "").lower()
    detail = str(phase.get("detail") or "")

    if not phase and findings == 0 and not os.path.isdir(os.path.join(rd, "nuclei")):
        track_state = "NOT_RUN"
    elif status in ("skipped", "not_run") or "skip" in detail.lower():
        track_state = "NOT_RUN"
    elif status == "error":
        track_state = "ERROR"
    elif err_rate is not None and err_rate >= 20:
        track_state = "DEGRADED"
    elif status == "partial":
        track_state = "PARTIAL"
    elif findings == 0 and status in ("ok", "success", "empty", ""):
        # 0 findings only EMPTY_VALID if not degraded
        if err_rate is not None and err_rate > 5:
            track_state = "DEGRADED"
        else:
            track_state = "EMPTY_VALID"
    elif findings > 0:
        track_state = "SUCCESS"
    else:
        track_state = "PARTIAL"

    out = {
        "schema": "bugbountyci.nuclei_track.v1",
        "track": "nuclei",
        "boundary": "Separate from core BBCI intelligence path; consume recon_export then optional Nuclei",
        "track_state": track_state,
        "findings_count": findings,
        "phase_status": phase.get("status"),
        "phase_detail": detail[:500] if detail else "",
        "error_rate_pct": err_rate,
        "note": (
            "findings_count=0 with DEGRADED/PARTIAL is NOT a clean target claim. "
            "Core recon export remains valid independent of this track."
        ),
    }
    os.makedirs(os.path.join(rd, "meta"), exist_ok=True)
    path = os.path.join(rd, "meta", "nuclei_track.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    args = ap.parse_args(argv)
    s = summarize(args.results_dir)
    print(f"✅ nuclei_track: state={s['track_state']} findings={s['findings_count']} err_rate={s['error_rate_pct']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
