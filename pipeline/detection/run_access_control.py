#!/usr/bin/env python3
"""
pipeline/detection/run_access_control.py

The CLI entrypoint that finally connects AccessControlEngine to a real
HTTP prober and the actual pipeline. Everything before this file was
either a skeleton (engine.py) or tested only with injected fake probers.

Prober behavior deliberately does NOT mirror pipeline/smart-fuzzing/
baseline.py's Tor-first pattern — see make_prober()'s docstring for why
this engine specifically needs DIRECT as the ground truth, with Tor only
as a last-resort fallback when DIRECT gets no response at all.

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
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pipeline.detection.engine import run_engines
from pipeline.detection.access_control_engine import AccessControlEngine


def make_prober(user_agent: str, use_tor: bool, timeout: int):
    """DIRECT is the ground truth for this engine, deliberately the
    OPPOSITE priority from baseline.py/live_host_probing.sh's Tor-first
    approach. Reasoning: this engine's whole job is comparing a blocked
    baseline against a mutation response — if the baseline came from one
    network path and the mutation check came from a different one (Tor
    vs DIRECT), a WAF that treats Tor exit nodes differently (a common,
    real behavior) can make an unrelated network-path difference look
    like a signal in EITHER direction:
      - a real bypass gets masked (Tor's own block page matches the
        baseline's status, so nothing looks different)
      - or an unrelated Tor-vs-DIRECT difference gets misread as a LEAD/
        HIGH_SIGNAL that has nothing to do with access control at all
    For initial host discovery (live_host_probing.sh) that risk doesn't
    apply the same way - there's no per-request baseline being compared
    against. Here, consistency between the two probes being diffed
    matters more than IP-diversity, and this engine's own request volume
    is small and capped (max_endpoints x mutations), so doubling nothing
    - DIRECT is simply tried first - is cheap. Tor is kept ONLY as a
    fallback for the rare case DIRECT itself gets no response at all.
    """
    def _curl(cmd_prefix, url):
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
            return None
        parts = out.rsplit("\n", 2) if out else []
        if len(parts) != 3:
            return None
        body, status_str, content_type = parts
        if not status_str.strip().isdigit():
            return None
        return {"status": int(status_str.strip()), "length": len(body),
                "content_type": content_type.strip() or "unknown"}

    def prober(url: str):
        result = _curl([], url)  # DIRECT first, always - the ground truth for this engine
        if result is not None:
            return result
        if use_tor:
            # DIRECT got nothing at all - Tor is better than no answer,
            # but this is the exception path, not the normal one.
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
