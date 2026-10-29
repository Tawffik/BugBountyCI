#!/usr/bin/env python3
"""Easy-Wins lane — Tips-style high-signal rollup before weak differentials.

Consumes existing artifacts only. LEAD/review — never CONFIRMED.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "bugbountyci.easy_wins.v1"
SENS = re.compile(
    r"(\.env|\.git|/backup|\.bak|\.sql|\.map(\?|$)|swagger|openapi|api-docs|"
    r"docker-compose|kubeconfig|\.gitlab-ci|Jenkinsfile|/metrics|/debug)",
    re.I,
)


def _lines(path: Path, limit: int = 50000) -> list[str]:
    if not path.is_file():
        return []
    out = []
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


def _load(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        j = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return j if isinstance(j, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _jsonl(path: Path, limit: int = 80) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(r, dict):
                    rows.append(r)
                if len(rows) >= limit:
                    break
    except OSError:
        return []
    return rows


def build(rd: Path) -> dict[str, Any]:
    items: list[dict[str, Any]] = []

    # Sensitive URL patterns from passive harvest
    for rel in ("urls/waymore.txt", "urls/gau.txt", "urls/wayback.txt", "urls/all.txt"):
        for u in _lines(rd / rel, 30000):
            if SENS.search(u):
                items.append(
                    {
                        "kind": "archive_sensitive_url",
                        "source": rel,
                        "value": u[:300],
                        "why": "Tips: historical/sensitive path pattern — probe live manually",
                    }
                )
                if sum(1 for i in items if i["kind"] == "archive_sensitive_url") >= 40:
                    break
        if sum(1 for i in items if i["kind"] == "archive_sensitive_url") >= 40:
            break

    # Derived path leads / maps
    der = _load(rd / "info_disclosure" / "derived_probes_summary.json") or {}
    for row in _jsonl(rd / "info_disclosure" / "derived_probes.jsonl"):
        disp = str(row.get("disposition") or row.get("status") or "")
        if disp in ("PATH_LEAD",) or row.get("kind") == "source_map" and row.get("status") == 200:
            items.append(
                {
                    "kind": "derived_probe",
                    "source": "derived_probes",
                    "value": str(row.get("url") or row.get("path") or "")[:300],
                    "why": f"disposition={disp} — review body (LEAD)",
                }
            )
            if sum(1 for i in items if i["kind"] == "derived_probe") >= 25:
                break
    # Archive sensitive live probes (Tips mile)
    for row in _jsonl(rd / "info_disclosure" / "archive_sensitive_probes.jsonl", 40):
        disp = str(row.get("disposition") or "")
        if disp in ("CONTENT_LEAD", "AUTH_OR_FORBIDDEN"):
            items.append(
                {
                    "kind": "archive_live_probe",
                    "source": "archive_sensitive_probes",
                    "value": f"{row.get('url')} [{row.get('status')}/{disp}]",
                    "why": f"snippet={(row.get('snippet') or '')[:120]} — LEAD, verify manually",
                }
            )
            if sum(1 for i in items if i["kind"] == "archive_live_probe") >= 25:
                break
    arch = _load(rd / "info_disclosure" / "archive_sensitive_summary.json") or {}
    if arch.get("leads") is not None:
        items.append(
            {
                "kind": "archive_live_probe",
                "source": "archive_sensitive_summary",
                "value": f"leads={arch.get('leads')} probed={arch.get('probed')}",
                "why": "Tips archive→live summary",
            }
        )

    if der.get("map_hits"):
        items.append(
            {
                "kind": "source_maps",
                "source": "derived_summary",
                "value": f"map_hits={der.get('map_hits')}",
                "why": "Source map hits — download and review (Tips JS)",
            }
        )

    # GitHub
    gh = _load(rd / "github_exposure" / "summary.json") or {}
    st = gh.get("provider_status") or "unknown"
    kept = int(gh.get("candidates_kept") or 0)
    if kept > 0:
        for row in _jsonl(rd / "github_exposure" / "candidates.jsonl", 20):
            items.append(
                {
                    "kind": "github_exposure",
                    "source": "github_exposure",
                    "value": str(row.get("html_url") or "")[:300],
                    "why": f"query={row.get('query_id')} — LEAD, do not use secrets",
                }
            )
    else:
        items.append(
            {
                "kind": "github_exposure",
                "source": "github_exposure",
                "value": f"status={st} kept=0",
                "why": "No API yield this run (often RATE_LIMIT) — use SMART_DORK_BOARD UI links",
            }
        )

    # Cloud clues only
    cloud = _load(rd / "detection" / "cloud_exposure_summary.json") or {}
    by = cloud.get("by_disposition") or {}
    if by:
        items.append(
            {
                "kind": "cloud_clue",
                "source": "cloud_exposure",
                "value": json.dumps(by),
                "why": "Provider clues only — 403≠open bucket; verify list/read manually",
            }
        )

    # Smart fuzz rollup
    sf = _load(rd / "smart-fuzzing" / "operator_summary.json") or {}
    if sf:
        items.append(
            {
                "kind": "smart_fuzz_health",
                "source": "smart-fuzzing/operator_summary.json",
                "value": (
                    f"wordlist={sf.get('wordlist_n')} wolf={sf.get('wolf_status')}/"
                    f"{sf.get('wolf_lines')} interesting={sf.get('interesting_n')}"
                ),
                "why": f"hosts={sf.get('hosts_count')} src={sf.get('hosts_source')} state={sf.get('pipeline_state')}",
            }
        )
    it_lines = _lines(rd / "smart-fuzzing" / "interesting.txt", 40)
    for line in it_lines[:15]:
        if line.startswith("#"):
            continue
        items.append(
            {
                "kind": "smart_fuzz_body",
        "smart_fuzz_interesting",
                "source": "smart-fuzzing/interesting.txt",
                "value": line[:250],
                "why": "Content-discovery signal — not a confirmed vulnerability",
            }
        )

    for row in _jsonl(rd / "smart-fuzzing" / "body_samples.jsonl", 20):
        if row.get("spa_like"):
            continue
        items.append(
            {
                "kind": "smart_fuzz_body",
                "source": "smart-fuzzing/body_samples.jsonl",
                "value": f"{row.get('url')} [{row.get('status')}]",
                "why": f"snippet={(row.get('snippet') or '')[:100]} — review only",
            }
        )
    # Secrets high
    sh = _lines(rd / "js" / "secrets_high.txt", 30)
    for s in sh[:15]:
        items.append(
            {
                "kind": "js_secret_candidate",
                "source": "js/secrets_high.txt",
                "value": s[:200],
                "why": "Secret-shaped string — review only, never authenticate with it",
            }
        )

    # Smart dork pointer
    if (rd / "triage" / "SMART_DORK_BOARD.md").is_file():
        items.append(
            {
                "kind": "dork_board",
                "source": "triage/SMART_DORK_BOARD.md",
                "value": "open SMART_DORK_BOARD",
                "why": "Multi-engine search URLs + any API hits",
            }
        )

    return {
        "schema": SCHEMA,
        "status": "OK",
        "count": len(items),
        "items": items[:120],
        "note": "Easy wins first — Tips lane. Not vulnerability confirmation.",
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# EASY_WINS — open this before Hunter differentials",
        "",
        report.get("note") or "",
        "",
        f"**Items:** {report.get('count', 0)}",
        "",
    ]
    by: dict[str, list] = {}
    for it in report.get("items") or []:
        by.setdefault(str(it.get("kind")), []).append(it)
    order = [
        "github_exposure",
        "derived_probe",
        "source_maps",
        "archive_live_probe",
        "archive_sensitive_url",
        "smart_fuzz_interesting",
        "smart_fuzz_health",
        "js_secret_candidate",
        "cloud_clue",
        "dork_board",
    ]
    for kind in order + [k for k in by if k not in order]:
        rows = by.get(kind) or []
        if not rows:
            continue
        lines.append(f"## {kind} ({len(rows)})")
        lines.append("")
        for r in rows[:30]:
            lines.append(f"- `{r.get('value')}`")
            lines.append(f"  - {r.get('why')} _(source: {r.get('source')})_")
        lines.append("")
    lines += [
        "## Next",
        "",
        "1. `triage/SMART_DORK_BOARD.md`",
        "2. `triage/QUALITY_GATE.md` / `GATE_0.md`",
        "3. `triage/DISCLOSURE_DESK.md`",
        "4. `detection/hunter_queue.md` (after easy wins)",
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
    (meta / "easy_wins.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (triage / "EASY_WINS.md").write_text(render_md(report), encoding="utf-8")
    print(json.dumps({"count": report["count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
