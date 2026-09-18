#!/usr/bin/env python3
"""
response_diff.py — V1

Compares each ffuf hit against that host's baseline (baseline.py) instead
of trusting status codes alone. This is what turns raw ffuf output into
"the ~40 candidates actually worth a human's time" instead of a
200/301/403 dump.

Classification (V1 keeps this simple; scoring/ranking is V3):
  - SPA_FALLBACK   fingerprint matches the host's baseline fingerprint
  - NOISE          status/length/content-type all close to baseline
  - INTERESTING    status, content-type, or length meaningfully differs
                    from baseline

Never says "vulnerability" — see the spec's core rule #4.

Inputs:
  <RD>/smart-fuzzing/baseline.json
  ffuf's own -o json output, one file per host (passed via --ffuf-json-dir)

Output:
  <RD>/smart-fuzzing/response_diffs.json   (full detail, per hit)
  <RD>/smart-fuzzing/interesting.txt       (human-readable shortlist)
"""
import argparse
import glob
import hashlib
import json
import os
import re


def fingerprint(body):
    normalized = re.sub(r"\d+", "", body or "")
    return hashlib.md5(normalized.encode("utf-8", "ignore")).hexdigest()


def classify(hit, base):
    if not base:
        return "UNKNOWN", "no baseline available for this host"

    reasons = []
    interesting = False

    if hit.get("fingerprint") and hit["fingerprint"] == base.get("fingerprint"):
        return "SPA_FALLBACK", "identical content fingerprint to baseline (likely catch-all response)"

    if hit["status"] != base["status"]:
        reasons.append(f"status {hit['status']} != baseline {base['status']}")
        interesting = True

    base_len = max(base.get("length", 0), 1)
    diff = abs(hit.get("length", 0) - base_len)
    if diff >= max(base_len * 0.15, 200):
        reasons.append(f"length differs by {diff} bytes from baseline")
        interesting = True

    hit_ct = (hit.get("content_type") or "").split(";")[0].strip()
    base_ct = (base.get("content_type") or "").split(";")[0].strip()
    if hit_ct and base_ct and hit_ct != base_ct:
        reasons.append(f"content-type {hit_ct} != baseline {base_ct}")
        interesting = True

    if interesting:
        return "INTERESTING", "; ".join(reasons)
    return "NOISE", "close to baseline on status/length/content-type"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--ffuf-json-dir", required=True,
                     help="directory of per-host ffuf -o json output files")
    args = ap.parse_args()

    out_dir = os.path.join(args.results_dir, "smart-fuzzing")
    os.makedirs(out_dir, exist_ok=True)

    baseline_path = os.path.join(out_dir, "baseline.json")
    baselines = {}
    if os.path.isfile(baseline_path):
        with open(baseline_path, "r", errors="ignore") as f:
            baselines = json.load(f)

    diffs = []
    for jf in glob.glob(os.path.join(args.ffuf_json_dir, "*.json")):
        try:
            with open(jf, "r", errors="ignore") as f:
                data = json.load(f)
        except Exception:
            continue

        base = None
        for candidate_host, b in baselines.items():
            if candidate_host.rstrip("/") in (data.get("config", {}) or {}).get("url", "") or True:
                # ffuf's own config.url carries the exact host used for this run;
                # fall back to a loose match if the naming scheme above misses it.
                if candidate_host.rstrip("/") in str(data.get("config", {}).get("url", "")):
                    base = b
                    break
        if base is None and len(baselines) == 1:
            base = next(iter(baselines.values()))

        for r in data.get("results", []):
            hit = {
                "url": r.get("url"),
                "status": r.get("status"),
                "length": r.get("length"),
                "content_type": r.get("content-type") or r.get("content_type"),
                "fingerprint": None,  # ffuf json doesn't include body; classified on status/length/type only
            }
            label, reason = classify(hit, base)
            diffs.append({**hit, "classification": label, "reason": reason})

    with open(os.path.join(out_dir, "response_diffs.json"), "w") as f:
        json.dump(diffs, f, indent=2)

    interesting = [d for d in diffs if d["classification"] == "INTERESTING"]
    with open(os.path.join(out_dir, "interesting.txt"), "w") as f:
        f.write("# INTERESTING RESPONSE (evidence-based, not a vulnerability claim)\n\n")
        for d in interesting:
            f.write(f"{d['url']} [{d['status']}] {d['length']} bytes\n  {d['reason']}\n\n")

    counts = {}
    for d in diffs:
        counts[d["classification"]] = counts.get(d["classification"], 0) + 1

    print(f"✅ response_diff done: {len(diffs)} hit(s) -> {counts} "
          f"({len(interesting)} INTERESTING written to interesting.txt)")


if __name__ == "__main__":
    main()
