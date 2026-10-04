#!/usr/bin/env python3
"""
historical_404_pivot.py — offline 404/410 → historical correlation

Uses ONLY artifacts already produced by the pipeline (no new scanners):
  - urls/wayback.txt, urls/gau.txt (historical surface)
  - urls/all.txt / live data (current surface)
  - optional: list of current 404/410 URLs if present

Does NOT claim historical URL = vulnerability.
Emits candidates + negative evidence into info_disclosure/historical_pivots.jsonl
and optional relationships via stdout counts.
"""
from __future__ import annotations

import argparse
import json
import os
from urllib.parse import urlparse


def read_urls(path, cap=20000):
    out = []
    if not path or not os.path.isfile(path):
        return out
    with open(path, "r", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= cap:
                break
            u = line.strip().split()[0] if line.strip() else ""
            if u.startswith("http"):
                out.append(u)
    return out


def path_key(u: str) -> str:
    try:
        p = urlparse(u)
        path = p.path or "/"
        # strip trailing slash except root
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        return path.lower()
    except Exception:
        return ""


def host_of(u: str) -> str:
    try:
        return (urlparse(u).hostname or "").lower()
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default="")
    args = ap.parse_args()
    rd = args.results_dir
    out_dir = os.path.join(rd, "info_disclosure")
    os.makedirs(out_dir, exist_ok=True)

    current = set(read_urls(os.path.join(rd, "urls", "all.txt")))
    current_paths = {path_key(u) for u in current if path_key(u)}
    current_hosts = {host_of(u) for u in current if host_of(u)}

    historical = []
    for name in ("wayback.txt", "gau.txt"):
        for u in read_urls(os.path.join(rd, "urls", name), cap=15000):
            historical.append((u, name))

    # Optional explicit 404 list from smart-fuzzing / probes
    not_found = []
    for rel in (
        "smart-fuzzing/interesting.txt",
        "info_disclosure/not_found.txt",
        "fuzzing/404.txt",
    ):
        p = os.path.join(rd, rel)
        if not os.path.isfile(p):
            continue
        with open(p, "r", errors="ignore") as f:
            for line in f:
                if "404" in line or "410" in line:
                    for tok in line.split():
                        if tok.startswith("http"):
                            not_found.append(tok.rstrip("],)"))

    pivots = []
    seen = set()
    # Historical paths not in current surface → STILL_MISSING / candidate for current check
    for u, src in historical:
        pk = path_key(u)
        if not pk or pk == "/" or len(pk) < 4:
            continue
        key = (pk, host_of(u) or src)
        if key in seen:
            continue
        seen.add(key)
        in_current = pk in current_paths
        host = host_of(u)
        host_related = host in current_hosts if host else False
        if in_current:
            classification = "STILL_LIVE"
            ladder = "OBSERVED"
            conf = "medium"
            next_pivot = "none_already_current"
        elif host_related:
            classification = "HISTORICAL_PATH_CURRENT_HOST"
            ladder = "CORRELATED"
            conf = "medium"
            next_pivot = "bounded_current_fetch"
        else:
            classification = "ARCHIVE_ONLY"
            ladder = "OBSERVED"
            conf = "low"
            next_pivot = "none_without_current_relation"

        pivots.append({
            "schema": "bugbountyci.historical_pivot.v1",
            "type": "historical_url_path",
            "url": u[:300],
            "path": pk[:200],
            "historical_source": src,
            "current_path_match": in_current,
            "current_host_relation": host_related,
            "classification": classification,
            "evidence_ladder": ladder,
            "confidence": conf,
            "next_pivot": next_pivot,
            "limitations": "historical presence alone is not a vulnerability; requires current validation",
            "provenance": f"urls/{src}",
        })
        if len(pivots) >= 500:
            break

    # Explicit 404/410 URLs correlated against historical path set
    hist_paths = {path_key(u) for u, _ in historical}
    for u in not_found[:100]:
        pk = path_key(u)
        if not pk:
            continue
        if pk in hist_paths:
            pivots.append({
                "schema": "bugbountyci.historical_pivot.v1",
                "type": "current_404_historical_hit",
                "url": u[:300],
                "path": pk[:200],
                "historical_source": "wayback_or_gau_path_match",
                "current_path_match": False,
                "classification": "404_WITH_HISTORY",
                "evidence_ladder": "CORRELATED",
                "confidence": "medium",
                "next_pivot": "recover_historical_content_then_current_check",
                "limitations": "404+history is investigation signal, not verified exposure",
                "provenance": "interesting_or_404_list+historical_urls",
            })

    out_path = os.path.join(out_dir, "historical_pivots.jsonl")
    with open(out_path, "w") as f:
        for row in pivots:
            f.write(json.dumps(row) + "\n")

    counts = {}
    for row in pivots:
        c = row.get("classification") or "UNKNOWN"
        counts[c] = counts.get(c, 0) + 1
    summary = {
        "schema": "bugbountyci.historical_pivot_summary.v1",
        "total": len(pivots),
        "counts": counts,
        "historical_inputs": sum(1 for _ in historical),
        "current_urls": len(current),
        "note": "Not a vulnerability report; correlation only",
    }
    with open(os.path.join(out_dir, "historical_pivot_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    print(f"✅ historical pivots: {len(pivots)} -> {counts}")


if __name__ == "__main__":
    main()
