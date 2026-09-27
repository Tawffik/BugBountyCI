#!/usr/bin/env python3
"""
pipeline/detection/run_ssrf.py

Wires SSRFEngine to a real HTTP prober, following the exact same
established pattern as run_access_control.py / run_open_redirect.py:
DIRECT is the ground truth, Tor only as a last-resort fallback when
DIRECT gets no response at all (see run_access_control.py's docstring
for why — Cloudflare-vs-Tor response differences would otherwise
contaminate the baseline comparison this engine also depends on).

Loads detection/parameter_intelligence.json (Priority 1 item #2,
already built) as the source of real endpoint->parameter pairs — this
engine does not independently re-derive parameters from urls/all.txt.
"""
import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pipeline.detection.engine import run_engines, write_phase_status, result_to_phase_status
from pipeline.detection.ssrf_engine import SSRFEngine


def make_prober(user_agent: str, use_tor: bool, timeout: int):
    def _curl(cmd_prefix, url):
        cmd = cmd_prefix + [
            "curl", "-sk", "--max-time", str(timeout), "-o", "-",
            "-H", f"User-Agent: {user_agent}",
            "-w", "\n__STATUS__:%{http_code}",
            url,
        ]
        start = time.time()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                     timeout=timeout + 5, errors="ignore")
            out = result.stdout
        except Exception:
            return None
        elapsed_ms = int((time.time() - start) * 1000)
        if not out or "__STATUS__:" not in out:
            return None
        body, _, status_part = out.rpartition("__STATUS__:")
        body = body.rstrip("\n")
        status_part = status_part.strip()
        if not status_part.isdigit():
            return None
        # Cap stored body size — this engine only needs to substring-
        # search for metadata markers, never the full page.
        return {"status": int(status_part), "body": body[:20000], "elapsed_ms": elapsed_ms}

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
    ap.add_argument("--oob-domain", default="",
                     help="this run's $OOB_DOMAIN from the 'OOB Setup (Interactsh)' "
                          "step, e.g. 'abc123.oast.fun'; empty means OOB wasn't "
                          "available this run and LEAD findings won't be escalated")
    args = ap.parse_args()

    rd = args.results_dir

    def load_json(path):
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, "r", errors="ignore") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    target_profile = load_json(os.path.join(rd, "smart-fuzzing", "target_profile.json"))
    vocabulary = load_json(os.path.join(rd, "smart-fuzzing", "vocabulary.json"))
    parameter_map = load_json(os.path.join(rd, "detection", "parameter_intelligence.json"))

    prober = make_prober(args.user_agent, args.use_tor, args.timeout)
    oob_correlation_path = os.path.join(rd, "ai_agent", "oob_correlation.jsonl")
    engine = SSRFEngine(prober=prober, parameter_map=parameter_map,
                         max_candidates=args.max_candidates,
                         oob_domain=args.oob_domain,
                         oob_correlation_path=oob_correlation_path)

    results = run_engines([engine], target_profile, vocabulary, results_dir=rd)
    r = results[0]

    status, detail = result_to_phase_status(r)
    write_phase_status(rd, "ssrf", status, detail)

    out_dir = os.path.join(rd, "detection")
    os.makedirs(out_dir, exist_ok=True)

    if not r.ran:
        print(f"⚠️ SSRF Engine did not run: {r.error}")
        return
    if r.error:
        print(f"ℹ️ SSRF Engine: {r.error}")
        return

    leads = [e for e in r.evidence if e.classification in ("LEAD", "HIGH_SIGNAL", "CONFIRMED")]
    leads.sort(key=lambda e: ("HIGH_SIGNAL", "CONFIRMED").count(e.classification), reverse=True)

    preview_path = os.path.join(out_dir, "hunter_queue_preview.txt")
    # Append — this shortlist is shared across engines, same as
    # run_access_control.py / run_open_redirect.py.
    with open(preview_path, "a") as f:
        f.write("\n# SSRF Intelligence — preview shortlist (V1)\n")
        f.write("# A response difference is a LEAD, not confirmed SSRF, unless the\n")
        f.write("# reason mentions an OOB callback registered — check\n")
        f.write("# ai_agent/oob_findings.txt (written by the 'OOB Check' step that\n")
        f.write("# runs later this same workflow) for an actual [OOB-CONFIRMED] hit.\n\n")
        for ev in leads:
            f.write(f"[{ev.classification}] {ev.candidate.metadata.get('endpoint')}\n")
            f.write(f"  parameter: {ev.candidate.metadata.get('parameter')}\n")
            f.write(f"  reason: {ev.reason}\n")
            f.write(f"  stable: {ev.stable}\n\n")

    print(f"✅ SSRF Engine: {r.candidates_generated} candidate(s) tested, "
          f"{len(r.evidence)} evidence item(s), {len(leads)} LEAD/HIGH_SIGNAL/CONFIRMED "
          f"appended to {preview_path}")


if __name__ == "__main__":
    main()
