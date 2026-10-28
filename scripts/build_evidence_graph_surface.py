#!/usr/bin/env python3
"""Evidence Graph operator surface — consume meta/relationships.jsonl only.

Does not invent edges. Summarizes existing export for triage.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "bugbountyci.evidence_graph_surface.v1"
SAMPLE = 25


def build(rd: Path) -> dict[str, Any]:
    path = rd / "meta" / "relationships.jsonl"
    if not path.is_file():
        return {
            "schema": SCHEMA,
            "status": "NOT_AVAILABLE",
            "detail": "meta/relationships.jsonl missing (exports may not have run yet)",
            "counts_by_type": {},
            "samples": [],
            "total": 0,
        }
    counts: Counter[str] = Counter()
    samples: list[dict[str, Any]] = []
    total = 0
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                total += 1
                t = str(row.get("type") or "UNKNOWN")
                counts[t] += 1
                if len(samples) < SAMPLE:
                    samples.append(
                        {
                            "type": t,
                            "from": str(row.get("from") or "")[:120],
                            "to": str(row.get("to") or "")[:160],
                        }
                    )
    except OSError as e:
        return {
            "schema": SCHEMA,
            "status": "ERROR",
            "detail": str(e),
            "counts_by_type": {},
            "samples": [],
            "total": 0,
        }
    return {
        "schema": SCHEMA,
        "status": "OK",
        "detail": "Edges from write_pipeline_exports only — not new recon",
        "counts_by_type": dict(counts.most_common()),
        "samples": samples,
        "total": total,
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# EVIDENCE_GRAPH — relationship rollup",
        "",
        f"**Status:** `{report.get('status')}`",
        "",
        str(report.get("detail") or ""),
        "",
        f"**Total edges:** {report.get('total', 0)}",
        "",
        "## Counts by type",
        "",
    ]
    c = report.get("counts_by_type") or {}
    if not c:
        lines.append("_No edges._")
    else:
        lines += ["| Type | Count |", "|------|------:|"]
        for k, v in c.items():
            lines.append(f"| `{k}` | {v} |")
    lines += ["", "## Sample edges", ""]
    for s in report.get("samples") or []:
        lines.append(f"- `{s.get('type')}`: `{s.get('from')}` → `{s.get('to')}`")
    if not report.get("samples"):
        lines.append("_No sample._")
    lines += [
        "",
        "## Note",
        "",
        "This is a **link layer** over existing artifacts, not a vulnerability claim.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    args = ap.parse_args()
    rd = Path(args.results_dir)
    triage, meta = rd / "triage", rd / "meta"
    triage.mkdir(parents=True, exist_ok=True)
    meta.mkdir(parents=True, exist_ok=True)
    report = build(rd)
    (meta / "evidence_graph.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (triage / "EVIDENCE_GRAPH.md").write_text(render_md(report), encoding="utf-8")
    print(json.dumps({"status": report["status"], "total": report.get("total", 0)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
