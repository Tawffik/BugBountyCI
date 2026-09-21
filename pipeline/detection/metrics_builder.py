#!/usr/bin/env python3
"""
pipeline/detection/metrics_builder.py

Priority 1 roadmap item (docs/V2_ROADMAP.md §6.1): a real Metrics
Baseline instead of judging every run qualitatively. Motivated
directly by manually reviewing okx.com's 6 "INTERESTING" hunter_queue
entries and discovering 5 of them were near-identical byte-length
diffs on the same 2 hosts — almost certainly one SPA catch-all-router
false-positive pattern reported 6 times, not 6 independent signals.
This file automates that exact analysis (near_duplicate_clusters)
instead of requiring a manual chart/eyeball review every time.

Reads:
  <RD>/detection/engine_results.json    (Access-Control, Open Redirect, ...)
  <RD>/smart-fuzzing/response_diffs.json (treated as a pseudo-engine
                                           'smart-fuzzing/response_diff'
                                           since it isn't on the
                                           Detection Engine Framework)

Writes:
  <RD>/detection/metrics.json
"""
import argparse
import json
import os
from collections import defaultdict


def load_engine_results(results_dir: str) -> list:
    path = os.path.join(results_dir, "detection", "engine_results.json")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", errors="ignore") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def load_smart_fuzzing_as_pseudo_engine(results_dir: str) -> dict:
    """response_diff.py isn't built on the Detection Engine Framework
    (it predates it), so it has no EngineRunResult of its own. This
    wraps its output into the same shape so it gets the same metrics
    treatment rather than being invisible to this file."""
    path = os.path.join(results_dir, "smart-fuzzing", "response_diffs.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", errors="ignore") as f:
            diffs = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    evidence = [{"classification": d.get("classification", "UNKNOWN"),
                 "candidate": {"target": d.get("url", "?")},
                 "reason": d.get("reason", ""), "stable": None} for d in diffs]
    return {"engine": "smart-fuzzing/response_diff", "ran": True, "error": None,
            "candidates_generated": len(diffs), "evidence": evidence, "duration_s": 0.0}


def _signal_precision(counts: dict) -> float:
    """(LEAD+HIGH_SIGNAL+CONFIRMED+INTERESTING) / total evidence.
    INTERESTING is response_diff.py's own legacy label (it predates the
    Detection Engine Framework's 5-label enum) — it means the same
    thing as LEAD/HIGH_SIGNAL (a real signal worth attention), so it
    must count here too. Found via a real bug on the first real test
    of this file (okx.com data): without this, a run with 6 genuine
    INTERESTING hits and 0 Framework-labeled evidence reported
    'signal precision: 0.0', which is simply wrong. NOISE/DUPLICATE/
    UNKNOWN still don't count. Returns 0.0 if there's no evidence at
    all (not None - a run with zero evidence has zero precision to
    report, not 'no data', so downstream consumers can always treat
    this as a number)."""
    total = sum(counts.values())
    if total == 0:
        return 0.0
    signal = (counts.get("LEAD", 0) + counts.get("HIGH_SIGNAL", 0)
              + counts.get("CONFIRMED", 0) + counts.get("INTERESTING", 0))
    return round(signal / total, 3)


def detect_near_duplicate_clusters(evidence: list, byte_tolerance: int = 500) -> list:
    """Groups INTERESTING/LEAD/HIGH_SIGNAL entries that mention a
    similar byte-length difference in their own reason text, clustered
    per host. This is exactly the manual analysis that flagged okx.com's
    6 hits as likely 2 real signals, not 6 - automated so it doesn't
    require a human chart every time.

    Deliberately simple (regex-free-ish, tolerant of missing data)
    rather than a precise re-implementation of response_diff.py's own
    diffing logic, which already lives in that file - this only reads
    what's already in the 'reason' string, it doesn't recompute
    anything."""
    import re
    by_host_bucket = defaultdict(list)
    for e in evidence:
        if e["classification"] not in ("INTERESTING", "LEAD", "HIGH_SIGNAL"):
            continue
        target = e.get("candidate", {}).get("target", "")
        m = re.search(r"differs by (\d+) bytes", e.get("reason", ""))
        if not m:
            continue
        byte_diff = int(m.group(1))
        try:
            from urllib.parse import urlsplit
            host = urlsplit(target).netloc or "unknown-host"
        except Exception:
            host = "unknown-host"
        bucket = byte_diff // byte_tolerance
        by_host_bucket[(host, bucket)].append({"target": target, "byte_diff": byte_diff})

    clusters = [{"host": host, "size": len(items), "byte_diff_range": byte_tolerance,
                 "targets": [i["target"] for i in items]}
                for (host, bucket), items in by_host_bucket.items() if len(items) >= 2]
    return sorted(clusters, key=lambda c: c["size"], reverse=True)


def build_metrics(results_dir: str) -> dict:
    engine_results = load_engine_results(results_dir)
    sf = load_smart_fuzzing_as_pseudo_engine(results_dir)
    if sf:
        engine_results = engine_results + [sf]

    per_engine = {}
    overall_counts = defaultdict(int)
    all_evidence_for_clustering = []

    for r in engine_results:
        counts = defaultdict(int)
        for e in r.get("evidence", []):
            counts[e.get("classification", "UNKNOWN")] += 1
            overall_counts[e.get("classification", "UNKNOWN")] += 1
        all_evidence_for_clustering.extend(r.get("evidence", []))

        per_engine[r["engine"]] = {
            "ran": r.get("ran", False),
            "error": r.get("error"),
            "candidates_generated": r.get("candidates_generated", 0),
            "evidence_count": len(r.get("evidence", [])),
            "classification_counts": dict(counts),
            "signal_precision": _signal_precision(counts),
            "duration_s": r.get("duration_s", 0.0),
        }

    clusters = detect_near_duplicate_clusters(all_evidence_for_clustering)
    total_signal = sum(overall_counts.get(c, 0) for c in ("LEAD", "HIGH_SIGNAL", "CONFIRMED", "INTERESTING"))

    return {
        "engines": per_engine,
        "overall": {
            "total_candidates": sum(p["candidates_generated"] for p in per_engine.values()),
            "total_evidence": sum(p["evidence_count"] for p in per_engine.values()),
            "classification_counts": dict(overall_counts),
            "signal_precision": _signal_precision(overall_counts),
            "raw_signal_count": total_signal,
            "likely_duplicate_clusters": clusters,
            "effective_signal_count_after_clustering": max(
                0, total_signal - sum(c["size"] - 1 for c in clusters)
            ),
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    args = ap.parse_args()

    metrics = build_metrics(args.results_dir)
    out_dir = os.path.join(args.results_dir, "detection")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "metrics.json")
    with open(out_path, "w") as f:
        json.dump(metrics, f, indent=2)

    o = metrics["overall"]
    print(f"✅ metrics.json written -> {out_path}")
    print(f"   signal precision: {o['signal_precision']} "
          f"({o['raw_signal_count']} raw signal / {o['total_evidence']} evidence)")
    if o["likely_duplicate_clusters"]:
        print(f"   ⚠️ {len(o['likely_duplicate_clusters'])} likely-duplicate cluster(s) found — "
              f"effective signal count after clustering: {o['effective_signal_count_after_clustering']} "
              f"(vs {o['raw_signal_count']} raw)")


if __name__ == "__main__":
    main()
