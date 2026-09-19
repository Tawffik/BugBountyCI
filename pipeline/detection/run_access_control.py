#!/usr/bin/env python3
"""
pipeline/detection/run_access_control.py

The CLI entrypoint that finally connects AccessControlEngine to a real
HTTP prober and the actual pipeline. Everything before this file was
either a skeleton (engine.py) or tested only with injected fake probers.

Prober behavior mirrors pipeline/smart-fuzzing/baseline.py and
scripts/live_host_probing.sh's established pattern in this repo: Tor
(proxychains4) by default, with a per-request DIRECT fallback if Tor
returns nothing — same reasoning as those two files (Tor for IP-based
WAF-block avoidance, DIRECT fallback because Tor is documented elsewhere
in this pipeline as occasionally returning 0 bytes).

Output:
  <RD>/detection/engine_results.json   (full evidence, from engine.py)
  <RD>/detection/hunter_queue_preview.txt   (LEAD/HIGH_SIGNAL only, for
                                              quick human review — this is
                                              NOT the real hunter_queue.md
                                              format from later phases,
                                              just a readable shortlist)
"""
import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pipeline.detection.engine import run_engines
from pipeline.detection.access_control_engine import AccessControlEngine


def make_prober(user_agent: str, use_tor: bool, timeout: int):
    def prober(url: str):
        cmd_prefix = ["proxychains4", "-q"] if use_tor else []
        cmd = cmd_prefix + [
            "curl", "-sk", "--max-time", str(timeout), "-L", "--max-redirs", "0",
            "-H", f"User-Agent: {user_agent}",
            "-w", "\n%{http_code}\n%{content_type}",
            url,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            out = result.stdout
        except Exception:
            out = ""

        parts = out.rsplit("\n", 2) if out else []
        status = None
        if len(parts) == 3:
            body, status_str, content_type = parts
            if status_str.strip().isdigit():
                status = int(status_str.strip())
        # Tor attempt produced nothing usable -> DIRECT fallback, same
        # per-request pattern already used in live_host_probing.sh.
        if status is None and use_tor:
            direct_cmd = cmd[2:]  # strip "proxychains4 -q"
            try:
                result = subprocess.run(direct_cmd, capture_output=True, text=True, timeout=timeout + 5)
                out = result.stdout
            except Exception:
                return None
            parts = out.rsplit("\n", 2) if out else []
            if len(parts) != 3:
                return None
            body, status_str, content_type = parts
            if not status_str.strip().isdigit():
                return None
            status = int(status_str.strip())

        if status is None:
            return None
        return {"status": status, "length": len(body), "content_type": content_type.strip() or "unknown"}

    return prober


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default="")
    ap.add_argument("--user-agent", default="Mozilla/5.0")
    ap.add_argument("--use-tor", action="store_true")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--max-endpoints", type=int, default=30)
    args = ap.parse_args()

    rd = args.results_dir

    def load_json(name):
        path = os.path.join(rd, "smart-fuzzing", name)
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, "r", errors="ignore") as f:
                return json.load(f)
        except Exception:
            return {}

    target_profile = load_json("target_profile.json")
    vocabulary = load_json("vocabulary.json")

    prober = make_prober(args.user_agent, args.use_tor, args.timeout)
    engine = AccessControlEngine(results_dir=rd, prober=prober, max_endpoints=args.max_endpoints)

    results = run_engines([engine], target_profile, vocabulary, results_dir=rd)
    r = results[0]

    out_dir = os.path.join(rd, "detection")
    os.makedirs(out_dir, exist_ok=True)

    if not r.ran:
        print(f"⚠️ Access-Control Engine did not run: {r.error}")
        return
    if r.error:  # prerequisites-not-met case, not a crash
        print(f"ℹ️ Access-Control Engine: {r.error}")
        return

    leads = [e for e in r.evidence if e.classification in ("LEAD", "HIGH_SIGNAL", "CONFIRMED")]
    leads.sort(key=lambda e: ("HIGH_SIGNAL", "CONFIRMED").count(e.classification), reverse=True)

    with open(os.path.join(out_dir, "hunter_queue_preview.txt"), "w") as f:
        f.write("# Access-Control Intelligence — preview shortlist (V1)\n")
        f.write("# A changed response is a signal, not a vulnerability.\n\n")
        for ev in leads:
            f.write(f"[{ev.classification}] {ev.candidate.target}\n")
            f.write(f"  original: {ev.candidate.metadata.get('original_url')}\n")
            f.write(f"  reason: {ev.reason}\n")
            f.write(f"  stable: {ev.stable}\n\n")

    print(f"✅ Access-Control Engine: {r.candidates_generated} candidate(s) tested, "
          f"{len(r.evidence)} evidence item(s), {len(leads)} LEAD/HIGH_SIGNAL/CONFIRMED "
          f"written to {out_dir}/hunter_queue_preview.txt")


if __name__ == "__main__":
    main()
