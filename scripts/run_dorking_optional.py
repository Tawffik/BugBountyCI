#!/usr/bin/env python3
"""Optional dorking runner with provider-status contracts (Phase 4).

NOT invoked by default Zero Track hunter. Used by dorking-optional.yml only.
Does not feed Hunter automatically.
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

API = "https://api.github.com/search/code"


def load_registry(path: Path) -> list[dict[str, Any]]:
    return list(json.loads(path.read_text(encoding="utf-8")).get("queries") or [])


def github_search(token: str, query: str, per_page: int = 5) -> tuple[str, list[dict], str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "BugBountyCI-dorking-optional",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    q = urllib.parse.urlencode({"q": query, "per_page": str(per_page)})
    req = urllib.request.Request(f"{API}?{q}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
            items = body.get("items") or []
            st = "COMPLETED_WITH_CANDIDATES" if items else "COMPLETED_ZERO"
            return st, items, f"total={body.get('total_count', 0)}"
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return "RATE_LIMIT", [], "403"
        if e.code == 401:
            return "ERROR", [], "401"
        return "ERROR", [], str(e.code)
    except Exception as e:
        return "ERROR", [], type(e).__name__


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN") or "")
    ap.add_argument(
        "--registry",
        default=str(Path(__file__).resolve().parents[1] / "config" / "dorking_query_registry.json"),
    )
    ap.add_argument("--max-per-query", type=int, default=5)
    args = ap.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    if not args.token:
        summary = {
            "schema": "bugbountyci.dorking_run_summary.v1",
            "provider_status": "NOT_CONFIGURED",
            "note": "No token — dorking not run",
        }
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary))
        return 0

    queries = load_registry(Path(args.registry))
    executions = []
    candidates = []
    for q in queries:
        if "github" not in (q.get("providers") or ["github"]):
            continue
        query = (q.get("template") or "").replace("{target}", args.target)
        status, items, detail = github_search(args.token, query, args.max_per_query)
        executions.append({
            "query_id": q.get("query_id"),
            "hypothesis": q.get("hypothesis"),
            "query": query,
            "provider_status": status,
            "detail": detail,
            "raw_items": len(items),
        })
        for it in items:
            html = it.get("html_url") or ""
            if args.target.lower() not in (html + str(it.get("repository", {}))).lower():
                continue
            candidates.append({
                "query_id": q.get("query_id"),
                "html_url": html,
                "repo": (it.get("repository") or {}).get("full_name"),
                "path": it.get("path"),
                "classification": "LEAD",
                "never_confirmed": True,
                "never_auto_hunter": True,
            })
        time.sleep(1.2)

    statuses = [e["provider_status"] for e in executions]
    if any(s == "COMPLETED_WITH_CANDIDATES" for s in statuses):
        overall = "COMPLETED_WITH_CANDIDATES"
    elif statuses and all(s == "COMPLETED_ZERO" for s in statuses):
        overall = "COMPLETED_ZERO"
    elif any(s == "RATE_LIMIT" for s in statuses):
        overall = "RATE_LIMIT"
    else:
        overall = "ERROR" if statuses else "NOT_RUN"

    summary = {
        "schema": "bugbountyci.dorking_run_summary.v1",
        "target": args.target,
        "provider_status": overall,
        "queries_run": len(executions),
        "candidates": len(candidates),
        "executions": executions,
        "note": "Optional workflow only — results are LEADs, not Hunter auto-feed",
    }
    with (out / "candidates.jsonl").open("w", encoding="utf-8") as fh:
        for c in candidates:
            fh.write(json.dumps(c) + "\n")
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"ok": True, "provider_status": overall, "candidates": len(candidates)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
