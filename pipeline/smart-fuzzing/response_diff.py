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
    """V2 response ranking: evidence-backed classes from status/length/content-type.

    A changed response is a signal, not a vulnerability. Labels are observational.
    """
    if base is None:
        return "UNKNOWN", "no exact-host baseline match available for this candidate's host"

    if body_available and hit.get("fingerprint") and hit["fingerprint"] == base.get("fingerprint"):
        return "SPA_FALLBACK", "identical content fingerprint to baseline (likely catch-all response)"

    status = hit.get("status")
    base_status = base.get("status")
    try:
        status_i = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_i = None
    try:
        base_status_i = int(base_status) if base_status is not None else None
    except (TypeError, ValueError):
        base_status_i = None

    # Status-first ranking when response diverges from baseline
    if status_i is not None and status_i != base_status_i:
        if status_i in (401, 407):
            return "AUTH_REQUIRED", f"status {status_i} != baseline {base_status} (auth challenge)"
        if status_i in (301, 302, 303, 307, 308):
            loc = (hit.get("location") or hit.get("redirect_location") or "")[:120]
            return "REDIRECT", f"status {status_i} != baseline {base_status}" + (f" loc={loc}" if loc else "")
        if status_i in (500, 502, 503, 504):
            return "SERVER_ERROR", f"status {status_i} != baseline {base_status}"
        if status_i in (403, 406, 429, 493):
            # 403 alone is not proof of WAF — label as WAF_BLOCK only when baseline was a normal success
            if base_status_i is not None and 200 <= base_status_i < 300:
                return "WAF_BLOCK", f"status {status_i} after baseline {base_status} (block/challenge vs prior success)"
            return "INTERESTING", f"status {status_i} != baseline {base_status}"

    reasons = []
    interesting = False

    if status_i is not None and status_i != base_status_i:
        reasons.append(f"status {status_i} != baseline {base_status}")
        interesting = True

    base_len = max(base.get("length", 0) or 0, 1)
    diff = abs((hit.get("length") or 0) - base_len)
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



def count_interesting_findings(interesting_path: str) -> int:
    """Count structured findings in interesting.txt — never header/comment lines."""
    if not os.path.isfile(interesting_path):
        return 0
    n = 0
    with open(interesting_path, "r", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            # Finding lines look like: URL [status] N bytes (CLASS)
            if s.startswith("http://") or s.startswith("https://"):
                n += 1
    return n


def aggregate_ffuf_raw(ffuf_json_dir: str) -> dict:
    """Summarize ffuf JSON outputs. Distinguish 0 files vs 0 matches after -ac."""
    files = sorted(glob.glob(os.path.join(ffuf_json_dir, "*.json"))) if ffuf_json_dir else []
    hosts = 0
    raw_matches = 0
    hosts_with_matches = 0
    autocalibration = None
    for path in files:
        try:
            with open(path, "r", errors="ignore") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        hosts += 1
        results = data.get("results") or []
        raw_matches += len(results)
        if results:
            hosts_with_matches += 1
        cfg = data.get("config") or {}
        if autocalibration is None and "autocalibration" in cfg:
            autocalibration = bool(cfg.get("autocalibration"))
    if hosts == 0:
        state = "NO_FFUF_OUTPUT"
    elif raw_matches == 0:
        state = "REQUESTS_EXECUTED_NO_MATCH"
    else:
        state = "MATCHES_CAPTURED"
    return {
        "ffuf_json_files": len(files),
        "hosts_fuzzed": hosts,
        "raw_match_count": raw_matches,
        "hosts_with_matches": hosts_with_matches,
        "autocalibration_enabled": autocalibration,
        "execution_state": state,
    }



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

    SIGNAL_CLASSES = ("INTERESTING", "AUTH_REQUIRED", "SERVER_ERROR", "REDIRECT")
    interesting = [d for d in diffs if d.get("classification") in SIGNAL_CLASSES]
    with open(os.path.join(out_dir, "interesting.txt"), "w") as f:
        f.write("# RANKED RESPONSE SIGNALS (evidence-based, not a vulnerability claim)\n")
        f.write("# A changed response is a signal, not a vulnerability.\n")
        f.write("# Classes: INTERESTING | AUTH_REQUIRED | SERVER_ERROR | REDIRECT\n")
        f.write("# WAF_BLOCK / SPA_FALLBACK / DUPLICATE / NOISE stay in response_diffs.json only.\n\n")
        for d in interesting:
            cls = d.get("classification", "INTERESTING")
            f.write(f"{d['url']} [{d['status']}] {d.get('length', 0)} bytes ({cls})\n  {d['reason']}\n\n")

    counts = {}
    for d in diffs:
        counts[d["classification"]] = counts.get(d["classification"], 0) + 1

    if unmatched_hosts:
        print(f"⚠️ {len(unmatched_hosts)} host(s) had no exact baseline match "
              f"(classified UNKNOWN, not guessed): {sorted(unmatched_hosts)[:5]}"
              f"{' ...' if len(unmatched_hosts) > 5 else ''}")

    ranking = {
        "schema": "bugbountyci.response_ranking.v2",
        "total": len(diffs),
        "counts": counts,
        "signal_count": len(interesting),
        "waf_dominated": (counts.get("WAF_BLOCK", 0) / max(len(diffs), 1)) >= 0.5,
        "notes": (
            "WAF_BLOCK majority — further path fuzzing on this host may be low information gain"
            if (counts.get("WAF_BLOCK", 0) / max(len(diffs), 1)) >= 0.5
            else ""
        ),
    }
    with open(os.path.join(out_dir, "response_ranking.json"), "w") as f:
        json.dump(ranking, f, indent=2)
        f.write("\n")

    # V3 compact historical outcome (no graph DB / giant memory)
    outcome = {
        "schema": "bugbountyci.strategy_outcome.v3",
        "strategy": "smart_fuzzing_response_diff",
        "total": len(diffs),
        "counts": counts,
        "useful_signals": len(interesting),
        "duplicate_rate": round(counts.get("DUPLICATE", 0) / max(len(diffs), 1), 3),
        "waf_rate": round(counts.get("WAF_BLOCK", 0) / max(len(diffs), 1), 3),
        "recommendation": (
            "reduce_generic_path_fuzzing"
            if ranking.get("waf_dominated")
            else "continue_target_aware"
        ),
    }
    ffuf_stats = aggregate_ffuf_raw(args.ffuf_json_dir)
    finding_count = count_interesting_findings(os.path.join(out_dir, "interesting.txt"))

    if ffuf_stats["execution_state"] == "NO_FFUF_OUTPUT":
        pipeline_state = "NO_FFUF_OUTPUT"
    elif ffuf_stats["raw_match_count"] == 0:
        pipeline_state = "REQUESTS_EXECUTED_NO_MATCH"
    elif len(diffs) == 0:
        pipeline_state = "MATCHES_CAPTURED_NO_DIFF_ROWS"
    elif finding_count == 0:
        pipeline_state = "NO_DIFFERENTIAL_SIGNAL"
    else:
        pipeline_state = "DIFFS_GENERATED"

    outcome["ffuf"] = ffuf_stats
    outcome["finding_count"] = finding_count
    outcome["pipeline_state"] = pipeline_state
    # useful_signals must match structured finding count, not header lines
    outcome["useful_signals"] = finding_count

    with open(os.path.join(out_dir, "strategy_outcome.json"), "w") as f:
        json.dump(outcome, f, indent=2)
        f.write("\n")

    metrics = {
        "schema": "bugbountyci.smart_fuzzing_metrics.v1",
        "pipeline_state": pipeline_state,
        "finding_count": finding_count,
        "diff_count": len(diffs),
        "classification_counts": counts,
        "ffuf": ffuf_stats,
        "note": (
            "finding_count counts http(s) result lines only — header/comment lines are not findings. "
            "REQUESTS_EXECUTED_NO_MATCH means ffuf ran and returned results=[] (often -ac filtering), "
            "not that the phase was skipped."
        ),
    }
    with open(os.path.join(out_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
        f.write("\n")

    ranking["finding_count"] = finding_count
    ranking["pipeline_state"] = pipeline_state
    ranking["ffuf"] = ffuf_stats
    with open(os.path.join(out_dir, "response_ranking.json"), "w") as f:
        json.dump(ranking, f, indent=2)
        f.write("\n")

    print(
        f"✅ response_diff done: state={pipeline_state} diffs={len(diffs)} "
        f"findings={finding_count} ffuf_raw_matches={ffuf_stats['raw_match_count']} "
        f"classes={counts}"
    )


if __name__ == "__main__":
    main()
