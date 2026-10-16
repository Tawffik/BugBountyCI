#!/usr/bin/env python3
"""Filter GitHub code-search hits for Zero Track (domain-scoped queries).

GitHub Code Search already matched the query against *file content*. Requiring
the target domain to also appear in repository.full_name or path was dropping
valid content hits (domain only in body). This filter:

  - drops known noise wordlist/domain-list repos
  - keeps domain-in-path/repo (strong attribution)
  - keeps secret-shaped paths even without domain in path (content was
    domain-scoped by the search query)
  - keeps base-token-in-repo for longer base names
  - records drop reasons for observability (not silent discard)

Does not confirm secrets or claim vulnerabilities — LEAD candidates only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

NOISE = re.compile(
    r"expired-domain|cirosantilli|domain-list|wordlist|secLists|payloads|"
    r"bug-bounty-wordlist|all\.txt|common\.txt|dirbuster|SecLists",
    re.I,
)
SECRET_PATH = re.compile(
    r"(?:^|/|\.)("
    r"env(?:\.[A-Za-z0-9_.-]+)?|"
    r"credentials?(?:\.[A-Za-z0-9_.-]+)?|"
    r"secrets?(?:\.[A-Za-z0-9_.-]+)?|"
    r"id_rsa|id_ed25519|private[._-]?key|\.pem|"
    r"aws|azure|gcp|service[_-]?account|"
    r"docker-compose|kubeconfig|\.npmrc|\.pypirc|"
    r"config\.(?:ya?ml|json|toml|ini|properties)|"
    r"settings\.(?:py|json|ya?ml)|"
    r"application\.(?:ya?ml|properties)|"
    r"backup|dump|\.sql"
    r")(?:$|/|\.)",
    re.I,
)


def _base_name(target: str) -> str:
    t = (target or "").lower().strip()
    t = re.sub(r"\.(com|net|org|io|co|dev|app|ch)(\.[a-z]{2})?$", "", t)
    return t.split(".")[-1] if t else ""


def decide(line: str, target: str, base: str) -> tuple[bool, str]:
    line = (line or "").strip()
    if not line:
        return False, "empty"
    if NOISE.search(line):
        return False, "noise_repo_or_path"
    low = line.lower()
    tgt = (target or "").lower()
    if tgt and tgt in low:
        return True, "domain_in_repo_or_path"
    repo, path = (line.split("::", 1) + [""])[:2]
    repo, path = repo.strip().lower(), path.strip().lower()
    if path and SECRET_PATH.search(path):
        # Search query was domain-scoped; path indicates credential-like file
        return True, "secret_path_under_domain_scoped_query"
    if base and len(base) >= 4 and base in repo:
        return True, "base_token_in_repo"
    return False, "weak_attribution"


def filter_lines(
    lines: list[str], target: str, *, limit: int = 80
) -> tuple[list[str], list[dict], dict]:
    base = _base_name(target)
    kept: list[str] = []
    dropped: list[dict] = []
    reasons: dict[str, int] = {}
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        key = line.lower()
        if key in seen:
            reasons["duplicate"] = reasons.get("duplicate", 0) + 1
            continue
        ok, reason = decide(line, target, base)
        reasons[reason] = reasons.get(reason, 0) + 1
        if ok:
            seen.add(key)
            kept.append(line)
        else:
            dropped.append({"line": line[:300], "reason": reason})
    kept = sorted(set(kept))[:limit]
    summary = {
        "schema": "bugbountyci.github_recon_filter.v1",
        "target": target,
        "base": base,
        "raw": len([l for l in lines if l.strip()]),
        "kept": len(kept),
        "dropped": len(dropped),
        "reasons": reasons,
        "limit": limit,
    }
    return kept, dropped, summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--dropped", default="")
    ap.add_argument("--summary", default="")
    ap.add_argument("--limit", type=int, default=80)
    args = ap.parse_args(argv)
    raw_path = Path(args.raw)
    lines = raw_path.read_text(errors="ignore").splitlines() if raw_path.is_file() else []
    kept, dropped, summary = filter_lines(lines, args.target, limit=args.limit)
    Path(args.out).write_text("\n".join(kept) + ("\n" if kept else ""))
    if args.dropped:
        Path(args.dropped).write_text(
            "\n".join(f"{d['reason']}\t{d['line']}" for d in dropped[:500])
            + ("\n" if dropped else "")
        )
    if args.summary:
        Path(args.summary).write_text(json.dumps(summary, indent=2) + "\n")
    print(
        f"GitHub recon filtered: {summary['kept']} kept / {summary['raw']} raw "
        f"(reasons={summary['reasons']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
