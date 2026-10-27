#!/usr/bin/env python3
"""P1b GitHub exposure slice — Playbook-aligned, provider-status honest."""
from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

API = "https://api.github.com/search/code"


def load_registry(path: Path) -> list[dict[str, Any]]:
    return list(json.loads(path.read_text(encoding="utf-8")).get("queries") or [])


def in_scope_url(blob: str, target: str) -> bool:
    t = (target or "").lower().strip()
    if not t or not blob:
        return False
    return t in blob.lower()


def redact(s: str, limit: int = 160) -> str:
    if not s:
        return ""
    s = re.sub(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*\S+", r"\1=[REDACTED]", s)
    s = re.sub(r"AKIA[0-9A-Z]{12,}", "AKIA[REDACTED]", s)
    return s[:limit]


def github_search(token: str, query: str, per_page: int = 5) -> tuple[str, list[dict[str, Any]], str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "BugBountyCI-github-exposure-slice",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    q = urllib.parse.urlencode({"q": query, "per_page": str(per_page)})
    req = urllib.request.Request(f"{API}?{q}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
            items = body.get("items") or []
            if not items:
                return "COMPLETED_ZERO", [], "total_count=%s" % body.get("total_count", 0)
            return "COMPLETED_WITH_CANDIDATES", items, "total_count=%s" % body.get("total_count", 0)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return "ERROR", [], "http_401"
        if e.code == 403:
            return "RATE_LIMIT", [], "http_403"
        if e.code == 422:
            return "ERROR", [], "http_422"
        return "ERROR", [], f"http_{e.code}"
    except Exception as e:
        return "ERROR", [], type(e).__name__


def run(rd: Path, target: str, token: str | None, registry_path: Path, max_per_query: int = 5) -> dict:
    out_dir = rd / "github_exposure"
    out_dir.mkdir(parents=True, exist_ok=True)
    (rd / "meta" / "phases").mkdir(parents=True, exist_ok=True)

    if not token:
        summary = {
            "schema": "bugbountyci.github_exposure_slice_summary.v1",
            "target": target,
            "provider_status": "NOT_CONFIGURED",
            "queries_run": 0,
            "candidates_kept": 0,
            "note": "GITHUB_TOKEN missing",
        }
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        (rd / "meta" / "phases" / "github_exposure_slice.json").write_text(
            json.dumps({"phase": "github_exposure_slice", "status": "NOT_CONFIGURED", "detail": "no token"}, indent=2) + "\n"
        )
        print(json.dumps(summary))
        return summary

    queries = load_registry(registry_path)
    executions = []
    kept_rows = []
    for q in queries:
        qid = q.get("query_id") or "unknown"
        query = (q.get("template") or "").replace("{target}", target)
        status, items, detail = github_search(token, query, per_page=max_per_query)
        exec_rec = {
            "query_id": qid,
            "family": q.get("family"),
            "hypothesis": q.get("hypothesis"),
            "query": query,
            "provider_status": status,
            "detail": detail,
            "raw_items": len(items),
            "kept": 0,
        }
        for it in items:
            html_url = it.get("html_url") or ""
            repo = (it.get("repository") or {}).get("full_name") or ""
            path = it.get("path") or ""
            if not in_scope_url(html_url + " " + repo + " " + path, target):
                continue
            kept_rows.append({
                "schema": "bugbountyci.github_exposure_candidate.v1",
                "query_id": qid,
                "family": q.get("family"),
                "hypothesis": q.get("hypothesis"),
                "evidence_type": q.get("evidence_type"),
                "html_url": html_url,
                "repo": repo,
                "path": path,
                "name": it.get("name"),
                "classification": "LEAD",
                "never_confirmed": True,
            })
            exec_rec["kept"] += 1
        executions.append(exec_rec)
        time.sleep(1.2)

    statuses = [e["provider_status"] for e in executions]
    if any(s == "COMPLETED_WITH_CANDIDATES" for s in statuses):
        overall = "COMPLETED_WITH_CANDIDATES"
    elif statuses and all(s == "COMPLETED_ZERO" for s in statuses):
        overall = "COMPLETED_ZERO"
    elif any(s == "RATE_LIMIT" for s in statuses):
        overall = "RATE_LIMIT"
    elif any(s == "ERROR" for s in statuses):
        overall = "PARTIAL" if any(str(s).startswith("COMPLETED") for s in statuses) else "ERROR"
    else:
        overall = statuses[0] if statuses else "NOT_RUN"

    summary = {
        "schema": "bugbountyci.github_exposure_slice_summary.v1",
        "target": target,
        "provider_status": overall,
        "queries_run": len(executions),
        "candidates_kept": len(kept_rows),
        "executions": executions,
        "playbook_source": "High-Signal Tips Playbook §2-3",
        "note": "LEAD only — do not use secrets; SI→Hunter OFF",
    }
    with (out_dir / "candidates.jsonl").open("w", encoding="utf-8") as fh:
        for r in kept_rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    (rd / "js").mkdir(parents=True, exist_ok=True)
    with (rd / "js" / "github_exposure_slice.txt").open("w", encoding="utf-8") as fh:
        for r in kept_rows[:80]:
            fh.write(f"{r.get('html_url')} # {r.get('query_id')} {r.get('repo')}/{r.get('path')}\n")
    # Compat for filter_github_recon: "repo :: path"
    with (rd / "js" / "github_recon_raw.txt").open("w", encoding="utf-8") as fh:
        for r in kept_rows[:120]:
            repo = r.get("repo") or ""
            path = r.get("path") or ""
            if repo or path:
                fh.write(f"{repo} :: {path}\n")
    phase_status = "ok" if overall in ("COMPLETED_ZERO", "COMPLETED_WITH_CANDIDATES") else str(overall).lower()
    (rd / "meta" / "phases" / "github_exposure_slice.json").write_text(
        json.dumps({"phase": "github_exposure_slice", "status": phase_status, "detail": f"status={overall} kept={len(kept_rows)}"}, indent=2) + "\n"
    )
    print(json.dumps({"ok": True, "provider_status": overall, "kept": len(kept_rows)}))
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "")
    ap.add_argument("--registry", default=str(Path(__file__).resolve().parents[1] / "config" / "github_exposure_queries.json"))
    ap.add_argument("--max-per-query", type=int, default=5)
    args = ap.parse_args()
    run(Path(args.results_dir), args.target, args.token or None, Path(args.registry), args.max_per_query)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
