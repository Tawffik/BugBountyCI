#!/usr/bin/env python3
"""Smart Dork Board — multi-engine operator queue + optional API yields.

Does NOT scrape Google/Bing (blocked/unreliable in CI). Emits ready-to-open
search URLs for: Google, Bing, DuckDuckGo, GitHub, GitLab, Docker Hub,
Kubernetes-ish web dorks.

Merges existing github_exposure / optional dorking candidates when present.
LEAD only — never CONFIRMED — never auto-Hunter feed.
"""
from __future__ import annotations

import argparse
import json
import urllib.parse
from pathlib import Path
from typing import Any

SCHEMA = "bugbountyci.smart_dork_board.v1"


def _q(s: str) -> str:
    return urllib.parse.quote_plus(s)


def search_urls(target: str) -> list[dict[str, str]]:
    t = target.strip()
    rows: list[dict[str, str]] = []

    def add(engine: str, family: str, query: str, url: str) -> None:
        rows.append({"engine": engine, "family": family, "query": query, "url": url})

    # Google
    g_queries = [
        ("disclosure", f'site:{t} ext:env OR filetype:env'),
        ("disclosure", f'site:{t} (\"api_key\" OR \"api-key\" OR secret)'),
        ("backup", f'site:{t} (ext:bak OR ext:sql OR ext:old OR \"index of\")'),
        ("api", f'site:{t} (swagger OR openapi OR \"api-docs\")'),
        ("cicd", f'\"{t}\" (\"gitlab-ci\" OR Jenkinsfile OR \"github/workflows\")'),
        ("cloud", f'\"{t}\" (s3.amazonaws.com OR storage.googleapis.com OR blob.core.windows.net)'),
        ("k8s", f'\"{t}\" (kubeconfig OR \"kind: Secret\" OR kubernetes.default.svc)'),
    ]
    for fam, query in g_queries:
        add("google", fam, query, f"https://www.google.com/search?q={_q(query)}")
        add("bing", fam, query, f"https://www.bing.com/search?q={_q(query)}")
        add("duckduckgo", fam, query, f"https://duckduckgo.com/?q={_q(query)}")

    # GitHub web UI (also works when API rate-limited)
    for fam, query in [
        ("disclosure", f'"{t}" filename:.env'),
        ("cicd", f'"{t}" path:.github/workflows'),
        ("cicd", f'"{t}" filename:docker-compose.yml'),
        ("cicd", f'"{t}" filename:.gitlab-ci.yml'),
        ("k8s", f'"{t}" kubeconfig'),
        ("api", f'"{t}" openapi OR swagger'),
    ]:
        add("github_ui", fam, query, f"https://github.com/search?type=code&q={_q(query)}")

    # GitLab public search
    for fam, query in [
        ("disclosure", f"{t} .env"),
        ("cicd", f"{t} .gitlab-ci.yml"),
        ("k8s", f"{t} kubeconfig"),
    ]:
        add("gitlab_ui", fam, query, f"https://gitlab.com/search?scope=blobs&search={_q(query)}")

    # Docker Hub
    add("docker_hub", "cicd", t, f"https://hub.docker.com/search?q={_q(t)}")

    return rows


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        j = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return j if isinstance(j, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _jsonl(path: Path, limit: int = 50) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out = []
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
                if isinstance(row, dict):
                    out.append(row)
                if len(out) >= limit:
                    break
    except OSError:
        return []
    return out


def build(rd: Path, target: str) -> dict[str, Any]:
    urls = search_urls(target)
    gh = _load_json(rd / "github_exposure" / "summary.json") or {}
    dork = _load_json(rd / "dorking" / "summary.json") or {}
    cands = _jsonl(rd / "github_exposure" / "candidates.jsonl") + _jsonl(
        rd / "dorking" / "candidates.jsonl"
    )
    return {
        "schema": SCHEMA,
        "target": target,
        "status": "OK",
        "note": (
            "Search-engine rows are operator links only (no scrape). "
            "API candidates merged when github_exposure/dorking ran. LEAD only."
        ),
        "operator_search_urls": urls,
        "github_api_status": gh.get("provider_status") or gh.get("status"),
        "github_candidates_kept": gh.get("candidates_kept"),
        "optional_dorking_status": dork.get("provider_status"),
        "api_candidates_sample": [
            {
                "html_url": c.get("html_url") or c.get("url"),
                "path": c.get("path"),
                "query_id": c.get("query_id"),
                "repo": c.get("repo") or c.get("repository"),
            }
            for c in cands[:30]
        ],
        "api_candidate_count": len(cands),
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# SMART_DORK_BOARD — multi-engine dork queue",
        "",
        f"**Target:** `{report.get('target')}`",
        "",
        report.get("note") or "",
        "",
        f"- GitHub API slice status: `{report.get('github_api_status')}`",
        f"- GitHub candidates kept: `{report.get('github_candidates_kept')}`",
        f"- Optional dorking status: `{report.get('optional_dorking_status')}`",
        f"- API candidate rows merged: `{report.get('api_candidate_count')}`",
        "",
        "## API / exposure hits (if any)",
        "",
    ]
    sample = report.get("api_candidates_sample") or []
    if not sample:
        lines.append("_None this run — open operator search URLs below (especially if RATE_LIMIT)._")
    for c in sample:
        lines.append(
            f"- `{c.get('query_id')}` {c.get('repo')}/{c.get('path')} — {c.get('html_url')}"
        )
    lines += ["", "## Operator search URLs (manual)", ""]
    by_eng: dict[str, list] = {}
    for row in report.get("operator_search_urls") or []:
        by_eng.setdefault(row["engine"], []).append(row)
    for eng, rows in by_eng.items():
        lines.append(f"### {eng}")
        lines.append("")
        for r in rows:
            lines.append(f"- **{r['family']}**: [{r['query'][:80]}]({r['url']})")
        lines.append("")
    lines += [
        "## Contracts",
        "",
        "- No Google HTML scrape in CI",
        "- Search hit ≠ vulnerability",
        "- Never use discovered secrets to log in",
        "- Not auto-fed to Hunter CONFIRMED",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default="")
    args = ap.parse_args()
    rd = Path(args.results_dir)
    target = args.target.strip()
    if not target:
        tp = rd / "meta" / "target.txt"
        if tp.is_file():
            target = tp.read_text(encoding="utf-8", errors="replace").strip().splitlines()[0]
    if not target:
        target = "UNKNOWN"
    triage, meta = rd / "triage", rd / "meta"
    triage.mkdir(parents=True, exist_ok=True)
    meta.mkdir(parents=True, exist_ok=True)
    report = build(rd, target)
    (meta / "smart_dork_board.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (triage / "SMART_DORK_BOARD.md").write_text(render_md(report), encoding="utf-8")
    (meta / "phases").mkdir(parents=True, exist_ok=True)
    (meta / "phases" / "smart_dork_board.json").write_text(
        json.dumps(
            {
                "phase": "smart_dork_board",
                "status": "ok",
                "detail": f"urls={len(report.get('operator_search_urls') or [])} api_cands={report.get('api_candidate_count')}",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"urls": len(report["operator_search_urls"]), "api": report["api_candidate_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
