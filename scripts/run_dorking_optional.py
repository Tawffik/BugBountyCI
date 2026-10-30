#!/usr/bin/env python3
"""Optional GitHub code-search dorking from config/dorking_query_registry.json.

Uses BBCI_GH_TOKEN / token arg. Provider status contract (Blueprint):
  NOT_CONFIGURED | ERROR | RATE_LIMIT | COMPLETED_ZERO | COMPLETED_WITH_CANDIDATES | PARTIAL

Never promotes to CONFIRMED. Soft-fail friendly.
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
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("queries") or [])


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
            total = body.get("total_count", 0)
            st = "COMPLETED_WITH_CANDIDATES" if items else "COMPLETED_ZERO"
            return st, items, f"total={total}"
    except urllib.error.HTTPError as e:
        retry = e.headers.get("Retry-After") if e.headers else None
        if e.code in (403, 429):
            return "RATE_LIMIT", [], f"http_{e.code} retry_after={retry}"
        if e.code == 401:
            return "ERROR", [], "http_401"
        if e.code == 422:
            return "ERROR", [], "http_422_query"
        return "ERROR", [], f"http_{e.code}"
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
    ap.add_argument("--sleep-sec", type=float, default=2.0, help="Delay between queries (rate limit hygiene)")
    args = ap.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    rd_meta = out.parent / "meta" / "phases" if out.name == "dorking" else out / "meta" / "phases"
    # Prefer results_dir/meta when output is .../dorking
    results_dir = out.parent if out.name == "dorking" else out
    phases = results_dir / "meta" / "phases"
    phases.mkdir(parents=True, exist_ok=True)

    if not args.token:
        summary = {
            "schema": "bugbountyci.dorking_run_summary.v1",
            "provider_status": "NOT_CONFIGURED",
            "note": "No token — dorking not run. Set BBCI_GH_TOKEN / WORKFLOW_PAT.",
        }
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        (phases / "dorking_optional.json").write_text(
            json.dumps({"phase": "dorking_optional", "status": "NOT_CONFIGURED", "detail": "no token"}, indent=2)
            + "\n"
        )
        print(json.dumps(summary))
        return 0

    reg_path = Path(args.registry)
    queries = load_registry(reg_path)
    try:
        max_q = int(json.loads(reg_path.read_text(encoding="utf-8")).get("default_max_queries") or 12)
    except Exception:
        max_q = 12
    max_q = int(os.environ.get("DORKING_MAX_QUERIES") or max_q)
    queries = [q for q in queries if "github" in (q.get("providers") or ["github"])]
    queries = sorted(queries, key=lambda q: int(q.get("priority") or 99))[: max(1, max_q)]

    executions = []
    candidates = []
    statuses: list[str] = []
    for i, q in enumerate(queries):
        if i and args.sleep_sec > 0:
            time.sleep(args.sleep_sec)
        qid = q.get("query_id") or "unknown"
        query = (q.get("template") or "").replace("{target}", args.target)
        status, items, detail = github_search(args.token, query, per_page=args.max_per_query)
        statuses.append(status)
        rec = {
            "query_id": qid,
            "family": q.get("family"),
            "hypothesis": q.get("hypothesis"),
            "query": query,
            "provider_status": status,
            "detail": detail,
            "raw_items": len(items),
        }
        executions.append(rec)
        for it in items:
            html_url = it.get("html_url") or ""
            repo = (it.get("repository") or {}).get("full_name") or ""
            path = it.get("path") or ""
            candidates.append(
                {
                    "schema": "bugbountyci.dorking_candidate.v1",
                    "query_id": qid,
                    "family": q.get("family"),
                    "hypothesis": q.get("hypothesis"),
                    "html_url": html_url,
                    "repository": repo,
                    "path": path,
                    "disposition": "LEAD",
                    "note": "Passive GitHub code search — not CONFIRMED; scope/ownership review required",
                }
            )
        if status == "RATE_LIMIT":
            # stop further queries to avoid hammering
            break

    if "RATE_LIMIT" in statuses and candidates:
        overall = "PARTIAL"
    elif "RATE_LIMIT" in statuses and not candidates:
        overall = "RATE_LIMIT"
    elif all(s == "COMPLETED_ZERO" for s in statuses) and statuses:
        overall = "COMPLETED_ZERO"
    elif any(s == "COMPLETED_WITH_CANDIDATES" for s in statuses):
        overall = "COMPLETED_WITH_CANDIDATES"
    elif any(s == "ERROR" for s in statuses):
        overall = "ERROR"
    else:
        overall = statuses[0] if statuses else "NOT_RUN"

    summary = {
        "schema": "bugbountyci.dorking_run_summary.v1",
        "target": args.target,
        "provider_status": overall,
        "queries_planned": len(queries),
        "queries_run": len(executions),
        "candidates": len(candidates),
        "note": "Registry from Notion Manual (domain-scoped). LEAD only.",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (out / "executions.json").write_text(json.dumps(executions, indent=2) + "\n")
    with (out / "candidates.jsonl").open("w", encoding="utf-8") as fh:
        for c in candidates:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")
    (phases / "dorking_optional.json").write_text(
        json.dumps(
            {
                "phase": "dorking_optional",
                "status": overall,
                "detail": f"queries={len(executions)} candidates={len(candidates)}",
            },
            indent=2,
        )
        + "\n"
    )
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
