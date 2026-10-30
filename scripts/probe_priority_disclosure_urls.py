#!/usr/bin/env python3
"""Probe priority/juicy sensitive URLs for disclosure leads (LEAD only).

Feeds info_disclosure/* hit files + probe_results.jsonl from URL priority
layers so disclosure is not limited to fixed path×10 hosts only.
"""
from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SENS = re.compile(
    r"(?i)(\.env|\.git|/backup|\.bak|\.sql|\.zip|\.tar|\.map(\?|$)|"
    r"swagger|openapi|api-docs|docker-compose|kubeconfig|"
    r"web\.config|phpinfo|\.aws/credentials|/metrics|/debug|"
    r"config\.(json|yml|yaml|php)|secrets\.(json|yml)|"
    r"/\.htaccess|id_rsa|\.pem(\?|$))",
)
SPA = ("<!doctype html", "<html", "__next_data__", 'id="root"')


def _fetch(url: str) -> tuple[int | None, str]:
    req = urllib.request.Request(
        url, headers={"User-Agent": "BugBountyCI-priority-disclosure"}, method="GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(6000).decode("utf-8", errors="replace")
            return getattr(resp, "status", None) or resp.getcode(), body
    except urllib.error.HTTPError as e:
        body = e.read(3000).decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        return e.code, body
    except Exception:
        return None, ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--budget", type=int, default=40)
    args = ap.parse_args()
    rd = Path(args.results_dir)
    out = rd / "info_disclosure"
    out.mkdir(parents=True, exist_ok=True)
    probe_path = out / "probe_results.jsonl"

    urls: list[str] = []
    seen: set[str] = set()
    for rel in (
        "urls/priority_high.txt",
        "urls/sensitive_files.txt",
        "urls/juicy.txt",
        "urls/wayback.txt",
    ):
        p = rd / rel
        if not p.is_file():
            continue
        for line in p.read_text(errors="replace").splitlines():
            u = line.strip()
            if not u.startswith("http") or u in seen:
                continue
            if not SENS.search(u):
                continue
            if len(u) > 280:
                continue
            seen.add(u)
            urls.append(u)
            if len(urls) >= args.budget * 3:
                break

    urls = urls[: max(1, args.budget)]
    leads = 0
    with probe_path.open("a", encoding="utf-8") as pf:
        for u in urls:
            st, body = _fetch(u)
            if st is None:
                continue
            low = body[:1500].lower()
            spa = any(m in low for m in SPA)
            row = {
                "url": u,
                "path": urlparse(u).path,
                "status": st,
                "family": "priority_url",
                "spa_like": spa,
                "source": "probe_priority_disclosure_urls",
            }
            pf.write(json.dumps(row, ensure_ascii=False) + "\n")
            if st != 200 or spa:
                continue
            path = urlparse(u).path.lower()
            if ".git" in path:
                (out / "git_exposure.txt").open("a").write(f"[GIT-EXPOSURE] {u}\n")
                leads += 1
            elif any(x in path for x in (".sql", ".bak", "backup", ".zip", ".tar")):
                (out / "backup_files.txt").open("a").write(f"[BACKUP] {u}\n")
                leads += 1
            elif any(x in path for x in (".env", "config", "secret", "web.config", "phpinfo", ".aws")):
                (out / "config_files.txt").open("a").write(f"[CONFIG] {u}\n")
                leads += 1
            else:
                leads += 1  # map/swagger still counted as probe lead

    summary = {
        "schema": "bugbountyci.priority_disclosure_probe.v1",
        "candidates": len(urls),
        "probed": len(urls),
        "content_leads": leads,
        "note": "LEAD only — not CONFIRMED. Prefers priority_high sensitive URLs.",
    }
    (out / "priority_disclosure_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
