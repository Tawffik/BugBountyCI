#!/usr/bin/env python3
"""
pipeline/detection/run_open_redirect.py

Wires OpenRedirectEngine to a real HTTP prober, following the exact same
established pattern as run_access_control.py: DIRECT is the ground
truth (this engine also diffs Location headers against expectations
across replay, so the Tor-vs-DIRECT WAF-difference risk that was fixed
in run_access_control.py applies here too), Tor only as a last-resort
fallback when DIRECT gets no response at all.

Never follows the redirect (no -L) — only reads the Location header.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pipeline.detection.engine import run_engines
from pipeline.detection.open_redirect_engine import OpenRedirectEngine


def make_prober(user_agent: str, use_tor: bool, timeout: int):
    def _curl(cmd_prefix, url):
        cmd = cmd_prefix + [
            "curl", "-sk", "--max-time", str(timeout), "-D", "-", "-o", "/dev/null",
            "-H", f"User-Agent: {user_agent}",
            "-w", "\n%{http_code}",
            url,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            out = result.stdout
        except Exception:
            return None
        if not out:
            return None
        lines = out.splitlines()
        if not lines:
            return None
        status_line = lines[-1].strip()
        if not status_line.isdigit():
            return None
        status = int(status_line)
        location = ""
        for line in lines[:-1]:
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
        return {"status": status, "location": location}

    def prober(url: str):
        result = _curl([], url)  # DIRECT first — see module docstring
        if result is not None:
            return result
        if use_tor:
            return _curl(["proxychains4", "-q"], url)
        return None

    return prober


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default="")
    ap.add_argument("--user-agent", default="Mozilla/5.0")
    ap.add_argument("--use-tor", action="store_true")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--max-candidates", type=int, default=60)
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
    engine = OpenRedirectEngine(prober=prober, max_candidates=args.max_candidates)

    results = run_engines([engine], target_profile, vocabulary, results_dir=rd)
    r = results[0]

    out_dir = os.path.join(rd, "detection")
    os.makedirs(out_dir, exist_ok=True)

    if not r.ran:
        print(f"⚠️ Open Redirect Engine did not run: {r.error}")
        return
    if r.error:
        print(f"ℹ️ Open Redirect Engine: {r.error}")
        return

    leads = [e for e in r.evidence if e.classification in ("LEAD", "HIGH_SIGNAL", "CONFIRMED")]
    leads.sort(key=lambda e: ("HIGH_SIGNAL", "CONFIRMED").count(e.classification), reverse=True)

    preview_path = os.path.join(out_dir, "hunter_queue_preview.txt")
    # Append (not overwrite) since run_access_control.py already writes
    # this same file for its own findings — both engines share one
    # human-readable shortlist for this V1 stage.
    with open(preview_path, "a") as f:
        f.write("\n# Open Redirect Intelligence — preview shortlist (V1)\n")
        f.write("# A changed response is a signal, not a vulnerability.\n\n")
        for ev in leads:
            f.write(f"[{ev.classification}] {ev.candidate.target}\n")
            f.write(f"  parameter: {ev.candidate.metadata.get('parameter')}\n")
            f.write(f"  reason: {ev.reason}\n")
            f.write(f"  stable: {ev.stable}\n\n")

    print(f"✅ Open Redirect Engine: {r.candidates_generated} candidate(s) tested, "
          f"{len(r.evidence)} evidence item(s), {len(leads)} LEAD/HIGH_SIGNAL/CONFIRMED "
          f"appended to {preview_path}")


if __name__ == "__main__":
    main()
