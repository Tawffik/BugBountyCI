#!/usr/bin/env python3
"""P2: bounded body samples for top INTERESTING hits (Intigriti-style read after fuzz).

Never labels vulnerability. Budget-capped. Soft-fail friendly.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

SPA = ("<!doctype html", "<html", 'id="root"', "id='root'", "__NEXT_DATA__")


def _load_diffs(path: str) -> list[dict[str, Any]]:
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", errors="ignore") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _fetch(url: str, timeout: float = 10.0) -> dict[str, Any]:
    req = urllib.request.Request(
        url, headers={"User-Agent": "BugBountyCI-smart-fuzz-body-sample"}, method="GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(6000)
            body = raw.decode("utf-8", errors="replace")
            return {"status": getattr(resp, "status", None) or resp.getcode(), "body": body, "error": None}
    except urllib.error.HTTPError as e:
        raw = e.read(3000) if hasattr(e, "read") else b""
        body = raw.decode("utf-8", errors="replace") if raw else ""
        return {"status": e.code, "body": body, "error": f"http_{e.code}"}
    except Exception as e:
        return {"status": None, "body": "", "error": type(e).__name__}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--budget", type=int, default=12)
    args = ap.parse_args()
    rd = args.results_dir
    sf = os.path.join(rd, "smart-fuzzing")
    os.makedirs(sf, exist_ok=True)
    diffs = _load_diffs(os.path.join(sf, "response_diffs.json"))
    interesting = [
        d
        for d in diffs
        if isinstance(d, dict)
        and str(d.get("classification") or "").upper() in ("INTERESTING", "AUTH_REQUIRED", "SERVER_ERROR")
    ]
    # Prefer shorter URLs / unique paths
    seen = set()
    planned = []
    for d in interesting:
        url = str(d.get("url") or d.get("input") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        planned.append(d)
        if len(planned) >= max(1, args.budget):
            break

    rows = []
    for d in planned:
        url = str(d.get("url") or "")
        r = _fetch(url)
        body = r.get("body") or ""
        low = body.lower()
        spa = any(m in low for m in SPA)
        rows.append(
            {
                "url": url,
                "prior_classification": d.get("classification"),
                "status": r.get("status"),
                "error": r.get("error"),
                "spa_like": spa,
                "snippet": re.sub(r"\s+", " ", body)[:200],
                "body_len": len(body),
                "never_confirmed": True,
            }
        )

    summary = {
        "schema": "bugbountyci.smart_fuzzing_body_samples.v1",
        "budget": args.budget,
        "candidates": len(interesting),
        "sampled": len(rows),
        "note": "Body samples for operator review — not vulnerability confirmation.",
    }
    with open(os.path.join(sf, "body_samples.jsonl"), "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    with open(os.path.join(sf, "body_samples_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
