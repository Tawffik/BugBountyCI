#!/usr/bin/env python3
"""Tips mile: filter passive URLs for sensitive patterns → bounded live probe → snippets.

Writes info_disclosure/archive_sensitive_probes.jsonl + summary.
Never CONFIRMED. Soft-fail friendly.
"""
from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SENS = re.compile(
    r"(\.env($|\?|\.)|\.git|/backup|\.bak($|\?)|\.sql($|\?)|\.map($|\?)|"
    r"swagger|openapi|api-docs|docker-compose|kubeconfig|"
    r"web\.config|phpinfo|\.aws/credentials|config\.(json|yml|php)|"
    r"secrets\.(json|yml)|/\.htaccess|"
    r"\.gitlab-ci|Jenkinsfile|/metrics|/debug/pprof)",
    re.I,
)
SPA_MARKERS = ("<!doctype html", "<html", "__NEXT_DATA__", "id=\"root\"", "id='root'")


def _lines(path: Path, limit: int) -> list[str]:
    if not path.is_file():
        return []
    out: list[str] = []
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if s:
                    out.append(s)
                if len(out) >= limit:
                    break
    except OSError:
        return []
    return out


def _fetch(url: str, timeout: float = 12.0) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "BugBountyCI-archive-sensitive-probe"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(8000)
            body = raw.decode("utf-8", errors="replace")
            return {
                "status": getattr(resp, "status", None) or resp.getcode(),
                "body": body,
                "error": None,
            }
    except urllib.error.HTTPError as e:
        raw = e.read(4000) if hasattr(e, "read") else b""
        body = raw.decode("utf-8", errors="replace") if raw else ""
        return {"status": e.code, "body": body, "error": f"http_{e.code}"}
    except Exception as e:
        return {"status": None, "body": "", "error": type(e).__name__}


def _disposition(status: int | None, body: str) -> str:
    b = (body or "")[:2000].lower()
    if status is None:
        return "ERROR"
    if any(m in b for m in SPA_MARKERS) and status in (200, 304):
        return "SPA_CATCHALL"
    if status == 200 and len(body.strip()) > 20 and not any(m in b for m in SPA_MARKERS):
        return "CONTENT_LEAD"
    if status in (401, 403):
        return "AUTH_OR_FORBIDDEN"
    if status == 404:
        return "NOT_FOUND"
    return f"STATUS_{status}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--budget", type=int, default=40)
    args = ap.parse_args()
    rd = Path(args.results_dir)
    out_dir = rd / "info_disclosure"
    out_dir.mkdir(parents=True, exist_ok=True)
    (rd / "meta" / "phases").mkdir(parents=True, exist_ok=True)

    candidates: list[str] = []
    seen: set[str] = set()
    for rel in ("urls/priority_high.txt", "urls/sensitive_files.txt", "urls/juicy.txt", "urls/waymore.txt", "urls/gau.txt", "urls/wayback.txt", "urls/all.txt"):
        for u in _lines(rd / rel, 80000):
            if not SENS.search(u):
                continue
            # prefer https, skip huge query noise
            if len(u) > 250:
                continue
            key = u.split("#")[0]
            if key in seen:
                continue
            seen.add(key)
            candidates.append(u)
            if len(candidates) >= args.budget * 3:
                break
        if len(candidates) >= args.budget * 3:
            break

    # Prefer shorter path-like URLs first
    candidates.sort(key=lambda x: (len(x), x))
    planned = candidates[: max(1, args.budget)]
    rows: list[dict[str, Any]] = []
    for u in planned:
        r = _fetch(u)
        disp = _disposition(r.get("status"), r.get("body") or "")
        snippet = (r.get("body") or "").replace("\n", " ")[:180]
        rows.append(
            {
                "url": u,
                "status": r.get("status"),
                "disposition": disp,
                "snippet": snippet,
                "error": r.get("error"),
                "classification": "LEAD" if disp in ("CONTENT_LEAD", "AUTH_OR_FORBIDDEN") else "OBSERVED",
                "never_confirmed": True,
            }
        )

    leads = [x for x in rows if x["disposition"] in ("CONTENT_LEAD", "AUTH_OR_FORBIDDEN")]
    summary = {
        "schema": "bugbountyci.archive_sensitive_probe.v1",
        "budget": args.budget,
        "candidates_considered": len(candidates),
        "probed": len(rows),
        "leads": len(leads),
        "by_disposition": {},
        "note": "Tips archive→live mile. LEAD only — not vulnerability confirmation.",
    }
    for x in rows:
        d = x["disposition"]
        summary["by_disposition"][d] = summary["by_disposition"].get(d, 0) + 1

    with (out_dir / "archive_sensitive_probes.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    (out_dir / "archive_sensitive_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (rd / "meta" / "phases" / "archive_sensitive_probe.json").write_text(
        json.dumps(
            {
                "phase": "archive_sensitive_probe",
                "status": "ok" if rows else "empty",
                "detail": f"probed={len(rows)} leads={len(leads)}",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"probed": len(rows), "leads": len(leads)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
