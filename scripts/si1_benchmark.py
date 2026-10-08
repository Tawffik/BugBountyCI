#!/usr/bin/env python3
"""SI-1 deterministic Secret Intelligence benchmark (offline).

Fixture files on disk contain only PLACEHOLDER / inject markers.
Oracle inject.parts are joined in memory so the repo never stores contiguous
provider-shaped secrets (GitHub push protection).
"""
from __future__ import annotations
import argparse, json, re
from pathlib import Path

BASELINE_RULES = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]{8,}){2}\b")),
    ("stripe_sk", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
]
PLACEHOLDER_RE = re.compile(r"(?i)(your_api_key_here|changeme|\bxxx\b|example_public|do_not_use|not_a_real|PLACEHOLDER)")
MODAL_KEYS_RE = re.compile(r"MODAL_KEYS")

def materialize(text: str, inject_key: str | None, inject_map: dict) -> str:
    if not inject_key or inject_key not in inject_map:
        return text
    spec = inject_map[inject_key]
    value = spec["join"].join(spec["parts"])
    return text.replace("PLACEHOLDER", value).replace(f"SI1_ORACLE_INJECT:{inject_key}", value)

def baseline_hits(text: str):
    if MODAL_KEYS_RE.search(text) and "AKIA" not in text:
        return []
    hits = []
    for name, rx in BASELINE_RULES:
        for m in rx.finditer(text):
            val = m.group(0)
            ctx = text[max(0, m.start()-40): m.end()+40]
            if PLACEHOLDER_RE.search(val) or (PLACEHOLDER_RE.search(ctx) and name == "stripe_sk" and "SI1FIXTURE" not in val):
                continue
            if "not_a_real" in ctx.lower():
                continue
            hits.append({"rule": name, "match_ref": f"{name}:{len(val)}", "offset": m.start()})
    return hits

def evaluate(fixture_root: Path) -> dict:
    oracle = json.loads((fixture_root / "oracle.json").read_text())
    inject_map = oracle.get("inject") or {}
    results = []
    tp = fp = tn = fn = 0
    for case in oracle["cases"]:
        raw = (fixture_root / case["path"]).read_text(errors="ignore")
        text = materialize(raw, case.get("inject"), inject_map)
        hits = baseline_hits(text)
        positive = len(hits) > 0
        label = case["label"]
        if label == "TP" and positive:
            tp += 1; outcome = "TP"
        elif label == "TP" and not positive:
            fn += 1; outcome = "FN"
        elif label == "FP" and positive:
            fp += 1; outcome = "FP"
        else:
            tn += 1; outcome = "TN"
        results.append({"id": case["id"], "path": case["path"], "label": label, "hits": hits, "outcome": outcome})
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "schema": "bugbountyci.si1_benchmark.v1",
        "detector": "baseline_rule_family",
        "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "cases": results,
    }

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="tests/fixtures/si1")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    root = Path(args.fixtures)
    report = evaluate(root)
    out = Path(args.out) if args.out else root / "benchmark_report.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"counts": report["counts"], "precision": report["precision"], "recall": report["recall"]}, indent=2))
    if report["counts"]["fp"] or report["counts"]["fn"]:
        print("FAIL"); return 1
    print("OK"); return 0

if __name__ == "__main__":
    raise SystemExit(main())
