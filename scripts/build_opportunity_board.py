#!/usr/bin/env python3
"""Opportunity Scoring v1 — prioritize *review time*, not vulnerability confirmation.

Sources (existing only):
  - meta/quality_gate.json
  - meta/delta.json
  - detection/hunter_queue.md / triage signals if present
  - meta/evidence_graph.json counts

Never emits CONFIRMED.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "bugbountyci.opportunity_board.v1"


def _load(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        j = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return j if isinstance(j, dict) else None
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def build(rd: Path) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    qg = _load(rd / "meta" / "quality_gate.json") or {}
    delta = _load(rd / "meta" / "delta.json") or {}
    graph = _load(rd / "meta" / "evidence_graph.json") or {}
    fg = _load(rd / "meta" / "funnel_gate.json") or {}

    # Integrity first
    ver = str(qg.get("verdict") or "")
    if ver and ver not in ("PASS",):
        items.append(
            {
                "rank": 0,
                "kind": "integrity",
                "title": f"Quality Gate: {ver}",
                "reasons": [qg.get("operator") or ver, "Fix honesty issues before chasing leads"],
                "score": 100,
            }
        )
    funnel = str(fg.get("verdict") or "")
    if funnel in ("STARVED", "ERROR", "PARTIAL"):
        items.append(
            {
                "rank": 0,
                "kind": "funnel",
                "title": f"Funnel: {funnel}",
                "reasons": ["Open GATE_0 before deep hunting"],
                "score": 95,
            }
        )

    # Delta focus
    if delta.get("status") == "OK":
        c = delta.get("counts") or {}
        added = int(c.get("hosts_added") or 0) + int(c.get("urls_added") or 0)
        if added > 0:
            items.append(
                {
                    "rank": 1,
                    "kind": "delta",
                    "title": "New surface since previous run",
                    "reasons": [
                        f"hosts_added={c.get('hosts_added', 0)}",
                        f"urls_added={c.get('urls_added', 0)}",
                        "Change ≠ vulnerability — review new hosts/URLs first",
                    ],
                    "score": min(90, 40 + min(added, 50)),
                    "samples": (delta.get("added_hosts") or [])[:10],
                }
            )
    elif delta.get("status") == "NOT_AVAILABLE":
        items.append(
            {
                "rank": 3,
                "kind": "delta",
                "title": "Delta not available",
                "reasons": ["No previous results dir — full surface review this run"],
                "score": 20,
            }
        )

    # Graph density as research context
    total_edges = int(graph.get("total") or 0)
    if total_edges > 0:
        types = graph.get("counts_by_type") or {}
        top = list(types.items())[:5]
        items.append(
            {
                "rank": 2,
                "kind": "graph",
                "title": f"Evidence graph: {total_edges} edges",
                "reasons": [f"{k}={v}" for k, v in top]
                + ["Use JS_TO_ENDPOINT / HOST links to prioritize manual checks"],
                "score": min(70, 25 + min(total_edges // 20, 40)),
            }
        )

    # Hunter file presence (lines as weak signal of queue density)
    hq = rd / "detection" / "hunter_queue.md"
    if hq.is_file():
        try:
            text = hq.read_text(encoding="utf-8", errors="replace")
            leads = len(re.findall(r"\bLEAD\b", text))
            hs = len(re.findall(r"HIGH_SIGNAL", text))
            if leads or hs:
                items.append(
                    {
                        "rank": 1,
                        "kind": "hunter",
                        "title": "Hunter queue has ranked signals",
                        "reasons": [
                            f"LEAD mentions≈{leads}",
                            f"HIGH_SIGNAL mentions≈{hs}",
                            "Open detection/hunter_queue.md — LEAD ≠ confirmed",
                        ],
                        "score": min(85, 50 + min(leads + hs, 30)),
                    }
                )
        except OSError:
            pass

    items.sort(key=lambda x: (-int(x.get("score") or 0), int(x.get("rank") or 9)))
    return {
        "schema": SCHEMA,
        "status": "OK",
        "detail": "Review prioritization only — never auto-CONFIRMED",
        "items": items[:20],
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# OPPORTUNITY — review priority board",
        "",
        str(report.get("detail") or ""),
        "",
        "> Scores order **human time**, not exploit certainty.",
        "",
    ]
    items = report.get("items") or []
    if not items:
        lines.append("_No prioritization signals from meta yet._")
    for i, it in enumerate(items, 1):
        lines.append(f"## {i}. {it.get('title')} (score {it.get('score')})")
        lines.append("")
        for r in it.get("reasons") or []:
            lines.append(f"- {r}")
        for s in it.get("samples") or []:
            lines.append(f"- sample: `{s}`")
        lines.append("")
    lines += [
        "## Open next",
        "",
        "1. `triage/QUALITY_GATE.md`",
        "2. `triage/GATE_0.md`",
        "3. `triage/DELTA.md` / `EVIDENCE_GRAPH.md`",
        "4. `detection/hunter_queue.md`",
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
    (meta / "opportunity_board.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (triage / "OPPORTUNITY.md").write_text(render_md(report), encoding="utf-8")
    print(json.dumps({"items": len(report.get("items") or [])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
