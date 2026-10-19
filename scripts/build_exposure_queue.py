#!/usr/bin/env python3
"""RRP-2: Unified operator exposure queue.

Merges info_disclosure hits, optional SECRETS_REVIEW JSON, and github_recon
into triage/EXPOSURE_QUEUE.md (top N, ranked). Classification stays REVIEW/LEAD
style — never CONFIRMED.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "bugbountyci.exposure_queue.v1"
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(\.env|env\.production|env\.staging|/\.git|backup|\.sql\.gz|"
    r"secrets?\.json|credentials|config\.ya?ml)"
)


def _lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        return [ln.strip() for ln in path.read_text(errors="ignore").splitlines() if ln.strip()]
    except OSError:
        return []


def _score(kind: str, path: str, detail: str) -> int:
    s = 10
    if kind == "info_disclosure":
        s += 40
    elif kind == "secret_review":
        s += 35
    elif kind == "github_recon":
        s += 25
    if SENSITIVE_PATH_RE.search(path) or SENSITIVE_PATH_RE.search(detail):
        s += 30
    if ".env" in path.lower() or ".env" in detail.lower():
        s += 15
    return s


def collect(results: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    id_dir = results / "info_disclosure"
    for name in ("config_files.txt", "git_exposure.txt", "backup_files.txt", "dir_listing.txt"):
        for ln in _lines(id_dir / name):
            items.append(
                {
                    "kind": "info_disclosure",
                    "source_file": f"info_disclosure/{name}",
                    "path": ln,
                    "detail": name,
                    "classification": "REVIEW",
                    "score": _score("info_disclosure", ln, name),
                }
            )

    # secrets_review.json from RRP-1 if present
    sr = results / "triage" / "secrets_review.json"
    if sr.is_file():
        try:
            data = json.loads(sr.read_text(encoding="utf-8", errors="replace"))
            for it in data.get("items") or []:
                path = str(it.get("path") or "")
                detail = str(it.get("rule") or it.get("source") or "")
                items.append(
                    {
                        "kind": "secret_review",
                        "source_file": "triage/secrets_review.json",
                        "path": path,
                        "detail": detail,
                        "classification": "REVIEW",
                        "score": _score("secret_review", path, detail),
                        "redacted": it.get("line_redacted"),
                    }
                )
        except (OSError, json.JSONDecodeError, ValueError):
            pass

    for name in ("github_recon.txt",):
        for base in (results / "js", results / "info_disclosure", results / "live"):
            for ln in _lines(base / name):
                items.append(
                    {
                        "kind": "github_recon",
                        "source_file": str(base.name + "/" + name),
                        "path": ln[:300],
                        "detail": "github_recon",
                        "classification": "REVIEW",
                        "score": _score("github_recon", ln, ""),
                    }
                )

    # dedupe by path+kind
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for it in sorted(items, key=lambda x: -x["score"]):
        key = f"{it['kind']}|{it['path']}|{it.get('detail')}"
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


def render_md(items: list[dict[str, Any]], limit: int = 30) -> str:
    lines = [
        "# EXPOSURE QUEUE (RRP-2)",
        "",
        f"**Items shown:** {min(limit, len(items))} / {len(items)}  ",
        "",
        "> Unified REVIEW queue — not CONFIRMED. Open context before any report.",
        "",
    ]
    if not items:
        lines += [
            "## Empty",
            "",
            "No info_disclosure / secrets_review / github_recon lines found.",
            "If GATE_0 is STARVED/ERROR, fix the funnel first.",
            "",
        ]
        return "\n".join(lines)

    for i, it in enumerate(items[:limit], 1):
        lines += [
            f"### {i}. [{it['score']}] `{it['kind']}`",
            f"- **path/url:** `{it.get('path', '')[:200]}`",
            f"- **from:** `{it.get('source_file')}`",
            f"- **detail:** {it.get('detail')}",
        ]
        if it.get("redacted"):
            lines.append(f"- **redacted:** `{it['redacted']}`")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--limit", type=int, default=30)
    args = ap.parse_args()
    results = Path(args.results_dir)
    triage = results / "triage"
    triage.mkdir(parents=True, exist_ok=True)
    items = collect(results)
    report = {
        "schema": SCHEMA,
        "count": len(items),
        "items": items[: max(args.limit * 3, 50)],
        "notes": ["Never CONFIRMED", "Prefer GATE_0 + SECRETS_REVIEW first"],
    }
    (triage / "exposure_queue.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (triage / "EXPOSURE_QUEUE.md").write_text(
        render_md(items, limit=args.limit), encoding="utf-8"
    )
    print(json.dumps({"count": len(items), "out": str(triage / "EXPOSURE_QUEUE.md")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
