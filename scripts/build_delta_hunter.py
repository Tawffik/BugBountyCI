#!/usr/bin/env python3
"""Delta Hunter v1 — compare current run surface to previous results dir.

Change alone is NOT a vulnerability. Output is research focus only.
If --prev-dir is missing, writes NOT_AVAILABLE (honest empty).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SCHEMA = "bugbountyci.delta_hunter.v1"


def _lines(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    try:
        return {ln.strip() for ln in path.open(encoding="utf-8", errors="replace") if ln.strip()}
    except OSError:
        return set()


def _sample(items: set[str], n: int = 30) -> list[str]:
    return sorted(items)[:n]


def build(curr: Path, prev: Path | None) -> dict[str, Any]:
    if prev is None or not prev.is_dir():
        return {
            "schema": SCHEMA,
            "status": "NOT_AVAILABLE",
            "detail": "No previous results dir — delta skipped (not a failure)",
            "added_hosts": [],
            "removed_hosts": [],
            "added_urls_sample": [],
            "counts": {},
        }

    c_hosts = _lines(curr / "subdomains" / "resolved.txt") or _lines(curr / "subdomains" / "all_subs.txt")
    p_hosts = _lines(prev / "subdomains" / "resolved.txt") or _lines(prev / "subdomains" / "all_subs.txt")
    c_urls = _lines(curr / "urls" / "all.txt")
    p_urls = _lines(prev / "urls" / "all.txt")
    c_live = _lines(curr / "live" / "hostname_targets.txt") or _lines(curr / "live" / "live.txt")
    p_live = _lines(prev / "live" / "hostname_targets.txt") or _lines(prev / "live" / "live.txt")

    added_hosts = c_hosts - p_hosts
    removed_hosts = p_hosts - c_hosts
    added_urls = c_urls - p_urls
    added_live = c_live - p_live

    return {
        "schema": SCHEMA,
        "status": "OK",
        "detail": "Surface delta only — not vulnerability evidence",
        "added_hosts": _sample(added_hosts, 50),
        "removed_hosts": _sample(removed_hosts, 50),
        "added_live_sample": _sample(added_live, 30),
        "added_urls_sample": _sample(added_urls, 40),
        "counts": {
            "hosts_curr": len(c_hosts),
            "hosts_prev": len(p_hosts),
            "hosts_added": len(added_hosts),
            "hosts_removed": len(removed_hosts),
            "urls_curr": len(c_urls),
            "urls_prev": len(p_urls),
            "urls_added": len(added_urls),
            "live_added": len(added_live),
        },
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# DELTA — vs previous run",
        "",
        f"**Status:** `{report.get('status')}`",
        "",
        str(report.get("detail") or ""),
        "",
        "> Change alone is **not** a vulnerability.",
        "",
    ]
    if report.get("status") == "NOT_AVAILABLE":
        lines.append("_Provide PREV_RESULTS_DIR or artifact from prior run to enable delta._")
        return "\n".join(lines) + "\n"
    c = report.get("counts") or {}
    lines += [
        "## Counts",
        "",
        f"| Metric | Value |",
        f"|--------|------:|",
        f"| hosts added | {c.get('hosts_added', 0)} |",
        f"| hosts removed | {c.get('hosts_removed', 0)} |",
        f"| urls added | {c.get('urls_added', 0)} |",
        f"| live surface added | {c.get('live_added', 0)} |",
        f"| urls curr / prev | {c.get('urls_curr', 0)} / {c.get('urls_prev', 0)} |",
        "",
        "## Sample new hosts",
        "",
    ]
    for h in report.get("added_hosts") or []:
        lines.append(f"- `{h}`")
    if not report.get("added_hosts"):
        lines.append("_None in sample window._")
    lines += ["", "## Sample new URLs", ""]
    for u in report.get("added_urls_sample") or []:
        lines.append(f"- `{u}`")
    if not report.get("added_urls_sample"):
        lines.append("_None in sample window._")
    lines += ["", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--prev-dir", default="")
    args = ap.parse_args()
    rd = Path(args.results_dir)
    prev = Path(args.prev_dir) if args.prev_dir else None
    triage = rd / "triage"
    meta = rd / "meta"
    triage.mkdir(parents=True, exist_ok=True)
    meta.mkdir(parents=True, exist_ok=True)
    report = build(rd, prev if prev and prev.is_dir() else None)
    (meta / "delta.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (triage / "DELTA.md").write_text(render_md(report), encoding="utf-8")
    print(json.dumps({"status": report["status"], "out": str(triage / "DELTA.md")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
