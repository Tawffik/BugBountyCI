#!/usr/bin/env python3
"""SI-2: canonical secret candidates from multi-detector hit lists.

Input: JSONL of detector observations (synthetic or tool output):
  {"detector":"gitleaks","rule":"...","file":"...","fingerprint":"...","match_ref":"..."}

Output: canonical candidates with merged detectors + provenance.
Does not write Hunter Queue. Does not claim CONFIRMED.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path


def canonical_id(file: str, match_ref: str) -> str:
    h = hashlib.sha256(f"{file}|{match_ref}".encode()).hexdigest()[:16]
    return f"sec_{h}"


def canonicalize(observations: list[dict]) -> list[dict]:
    buckets: dict[str, dict] = {}
    for obs in observations:
        file = str(obs.get("file") or obs.get("path") or "")
        match_ref = str(obs.get("match_ref") or obs.get("rule") or obs.get("Secret") or "")
        # Prefer fingerprint if present
        fp = str(obs.get("fingerprint") or "")
        key = fp if fp else f"{file}|{match_ref}"
        cid = canonical_id(file, key)
        if cid not in buckets:
            buckets[cid] = {
                "schema": "bugbountyci.secret_candidate.v1",
                "candidate_id": cid,
                "file": file,
                "match_ref": match_ref,
                "detectors": [],
                "rules": [],
                "classification": "LEAD",  # never CONFIRMED from pattern alone
                "currentness": "NOT_CHECKED",
                "capability": "NOT_CHECKED",
                "confidence": 0.4,
                "provenance": [],
                "why_interesting": "pattern observation from detector(s)",
                "why_maybe_benign": "may be public config, placeholder, or false positive",
                "next_authorized_action": "human review of context; no uncontrolled validation",
            }
        det = str(obs.get("detector") or "unknown")
        rule = str(obs.get("rule") or "")
        if det not in buckets[cid]["detectors"]:
            buckets[cid]["detectors"].append(det)
        if rule and rule not in buckets[cid]["rules"]:
            buckets[cid]["rules"].append(rule)
        buckets[cid]["provenance"].append({
            "detector": det,
            "rule": rule,
            "file": file,
            "run_id": obs.get("run_id"),
        })
        # corroboration raises confidence but never to CONFIRMED
        n = len(buckets[cid]["detectors"])
        buckets[cid]["confidence"] = min(0.85, 0.4 + 0.15 * (n - 1))
        if n >= 2:
            buckets[cid]["classification"] = "HIGH_SIGNAL"
            buckets[cid]["why_interesting"] = "corroborated by multiple detectors"
    return list(buckets.values())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="JSONL detector observations")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rows = []
    for line in Path(args.input).read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    cands = canonicalize(rows)
    Path(args.out).write_text(json.dumps({"schema": "bugbountyci.secret_candidates.v1", "candidates": cands}, indent=2) + "\n")
    print(f"observations={len(rows)} canonical={len(cands)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
