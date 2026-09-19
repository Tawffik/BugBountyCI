#!/usr/bin/env python3
"""
response_diff.py — V1 (fixed)

Compares each ffuf hit against that EXACT host's baseline (baseline.py)
instead of trusting status codes alone.

Fix history:
  V1.0 had a baseline-matching bug: the host-lookup loop contained an
  `or True` that made the "does this candidate host match this baseline
  host" check always true, so with >1 host in a run, a candidate could
  silently get scored against the WRONG host's baseline. Confirmed on a
  real run (superdrug.com, 2025-09-19): 21/21 ffuf hits came back
  INTERESTING (100%), which is not a plausible real distribution and
  pointed straight at broken matching.

  That run also exposed a second, real issue: a WAF/generic block page
  returned for ~20 different "_admin*" path variants on the same host,
  all with near-identical status+length. Each was being reported as its
  own "INTERESTING" lead — i.e. one block page counted 20 times. V1 has
  no WAF-fingerprint module yet (that's a later phase), so the fix here
  is a simple, deterministic one: within a single host, hits that share
  the same (status, length) as an earlier hit are DUPLICATE, not new
  signals. This does not require any new dependency or heuristic beyond
  what V1 already computes.

Classification:
  - SPA_FALLBACK   fingerprint matches the host's baseline fingerprint
                    (only possible when a body fingerprint is available —
                    see body_available below)
  - DUPLICATE      same (status, length) already seen on this host in
                    this run (repeated block/error page, not a new signal)
  - NOISE          status/length/content-type all close to baseline
  - INTERESTING    status, content-type, or length meaningfully differs
                    from baseline
  - UNKNOWN        no baseline could be matched to this exact host —
                    V1 does NOT guess using another host's baseline

Never says "vulnerability" — see the spec's core rule #4 / Golden Rule.

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
from collections import defaultdict
from urllib.parse import urlsplit


def fingerprint(body):
    normalized = re.sub(r"\d+", "", body or "")
    return hashlib.md5(normalized.encode("utf-8", "ignore")).hexdigest()


def normalize_host(url):
    """https://api.example.com/FUZZ -> https://api.example.com
    Used for EXACT matching against baseline.json's keys. No fuzzy /
    substring matching — that's what caused the original bug."""
    if not url:
        return None
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def classify(hit, base, body_available):
    if base is None:
        return "UNKNOWN", "no exact-host baseline match available for this candidate's host"

    reasons = []
    interesting = False

    if body_available and hit.get("fingerprint") and hit["fingerprint"] == base.get("fingerprint"):
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
    # Baseline keys are stored as scheme://host (see baseline.py's --hosts-file
    # input); normalize once so lookups are exact string matches only.
    baselines_by_host = {normalize_host(h + "/"): b for h, b in baselines.items()}

    # ffuf's raw json never includes response bodies, so there is no real
    # body to fingerprint here. Being explicit about this (rather than
    # quietly leaving fingerprint=None) is deliberate: V1 does status/
    # length/content-type diffing only, and SPA_FALLBACK via fingerprint
    # match is consequently unreachable until a future phase adds body
    # capture. That's stated in the README too.
    BODY_AVAILABLE = False

    diffs = []
    seen_per_host = defaultdict(list)   # host -> [(status, length), ...] representatives
    unmatched_hosts = set()
    LENGTH_TOLERANCE = 15  # bytes; the same block/error page often varies a few
                           # bytes with the requested path's own length (echoed
                           # in the page, or padding) — this clusters those
                           # together instead of over-counting near-identical pages

    for jf in glob.glob(os.path.join(args.ffuf_json_dir, "*.json")):
        try:
            with open(jf, "r", errors="ignore") as f:
                data = json.load(f)
        except Exception:
            continue

        config_url = (data.get("config") or {}).get("url", "")
        candidate_host = normalize_host(config_url)
        base = baselines_by_host.get(candidate_host) if candidate_host else None
        if candidate_host and base is None:
            unmatched_hosts.add(candidate_host)

        for r in data.get("results", []):
            hit = {
                "url": r.get("url"),
                "status": r.get("status"),
                "length": r.get("length"),
                "content_type": r.get("content-type") or r.get("content_type"),
                "fingerprint": None,  # see BODY_AVAILABLE note above
            }

            dedup_key = (hit["status"], hit["length"])
            host_key = candidate_host or "unknown-host"
            match = next(
                (rep for rep in seen_per_host[host_key]
                 if rep[0] == dedup_key[0] and abs(rep[1] - dedup_key[1]) <= LENGTH_TOLERANCE),
                None,
            )
            if match is not None:
                diffs.append({
                    **hit,
                    "body_available": BODY_AVAILABLE,
                    "classification": "DUPLICATE",
                    "reason": f"status+length within {LENGTH_TOLERANCE} bytes of an earlier hit on this host "
                              f"(status={match[0]}, ~{match[1]} bytes) — "
                              f"likely one block/error page matched by multiple candidates, not a new signal",
                })
                continue
            seen_per_host[host_key].append(dedup_key)

            label, reason = classify(hit, base, BODY_AVAILABLE)
            diffs.append({**hit, "body_available": BODY_AVAILABLE, "classification": label, "reason": reason})

    with open(os.path.join(out_dir, "response_diffs.json"), "w") as f:
        json.dump(diffs, f, indent=2)

    interesting = [d for d in diffs if d["classification"] == "INTERESTING"]
    with open(os.path.join(out_dir, "interesting.txt"), "w") as f:
        f.write("# INTERESTING RESPONSE (evidence-based, not a vulnerability claim)\n")
        f.write("# A changed response is a signal, not a vulnerability.\n\n")
        for d in interesting:
            f.write(f"{d['url']} [{d['status']}] {d['length']} bytes\n  {d['reason']}\n\n")

    counts = {}
    for d in diffs:
        counts[d["classification"]] = counts.get(d["classification"], 0) + 1

    if unmatched_hosts:
        print(f"⚠️ {len(unmatched_hosts)} host(s) had no exact baseline match "
              f"(classified UNKNOWN, not guessed): {sorted(unmatched_hosts)[:5]}"
              f"{' ...' if len(unmatched_hosts) > 5 else ''}")

    print(f"✅ response_diff done: {len(diffs)} hit(s) -> {counts} "
          f"({len(interesting)} INTERESTING written to interesting.txt)")


if __name__ == "__main__":
    main()
