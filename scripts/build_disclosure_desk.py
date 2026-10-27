#!/usr/bin/env python3
"""P0 Disclosure Desk — one operator surface for the information-disclosure family.

Reads existing artifacts only (no new active probes). Never emits CONFIRMED.
See docs/INFO_DISCLOSURE_EXECUTION_PLAN.md Phase 1.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA = "bugbountyci.disclosure_desk.v1"
CAP = 25


def _lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    except OSError:
        return []


def _count(path: Path) -> int:
    return len(_lines(path))


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _jsonl(path: Path, limit: int = 500) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    rows.append(rec)
                if len(rows) >= limit:
                    break
    except OSError:
        pass
    return rows


def build(results_dir: Path) -> dict[str, Any]:
    rd = results_dir
    idir = rd / "info_disclosure"
    sections: dict[str, Any] = {}

    # Path probes
    path_files = {
        "git_exposure": idir / "git_exposure.txt",
        "backup_files": idir / "backup_files.txt",
        "config_files": idir / "config_files.txt",
        "dir_listing": idir / "dir_listing.txt",
        "error_disclosure": idir / "error_disclosure.txt",
    }
    path_hits = {k: _lines(p)[:CAP] for k, p in path_files.items()}
    path_counts = {k: _count(p) for k, p in path_files.items()}
    sections["path_probes"] = {
        "counts": path_counts,
        "samples": path_hits,
        "total_hits": sum(path_counts.values()),
        "note": "EMPTY_VALID on hardened targets is not proof the stage failed.",
    }

    # Secrets
    secrets_high = _lines(rd / "js" / "secrets_high.txt")[:CAP]
    si4 = _load_json(rd / "meta" / "secret_candidates_si4.json")
    sections["secrets"] = {
        "secrets_high_count": _count(rd / "js" / "secrets_high.txt"),
        "secrets_high_sample": secrets_high,
        "si4_present": si4 is not None,
        "full_review": "triage/SECRETS_REVIEW.md",
        "note": "Candidates for human review — SI→Hunter remains OFF.",
    }

    # Source maps
    sm = _lines(rd / "source_maps" / "found.txt")[:CAP]
    sections["source_maps"] = {
        "count": _count(rd / "source_maps" / "found.txt"),
        "sample": sm,
        "note": "Presence is a lead; sensitivity depends on map contents.",
    }

    # GitHub recon
    gh_kept = _lines(rd / "js" / "github_recon.txt")[:CAP]
    if not gh_kept:
        gh_kept = _lines(rd / "github_recon" / "kept.txt")[:CAP]
    sections["github_recon"] = {
        "count": len(gh_kept) if gh_kept else _count(rd / "js" / "github_recon.txt"),
        "sample": gh_kept,
        "note": "Passive public references — not confirmed exposure impact.",
    }

    # Historical
    piv = _load_json(idir / "historical_pivot_summary.json") or {}
    val = _load_json(idir / "historical_validation_summary.json") or {}
    sections["historical"] = {
        "pivot_summary": piv,
        "validation_summary": val,
        "note": "Correlation / reachability budget — not vulnerability counts.",
    }

    # Cloud
    cloud = _load_json(rd / "detection" / "cloud_exposure_summary.json") or {}
    cloud_rows = _jsonl(rd / "detection" / "cloud_exposure_findings.jsonl", limit=200)
    strong = []
    for row in cloud_rows:
        disp = row.get("final_disposition") or ""
        if disp in ("content_supported", "listing_evidence", "exposure_lead") or (
            disp == "provider_clue"
            and (row.get("probe") or {}).get("response_class") in ("access_denied", "listing_evidence", "content_200")
        ):
            strong.append(
                {
                    "asset": row.get("asset_normalized") or row.get("host"),
                    "disposition": disp,
                    "provider": row.get("provider_hypothesis"),
                }
            )
        if len(strong) >= CAP:
            break
    sections["cloud"] = {
        "summary": cloud,
        "strong_clues_sample": strong,
        "note": "403/AccessDenied is an existence clue only — never auto-confirmed.",
    }

    # LinkFinder / JS endpoints
    endpoints = _lines(rd / "js" / "endpoints.txt")[:CAP]
    lf_sum = _load_json(rd / "js_deep" / "linkfinder_summary.json") or {}
    sections["js_endpoints"] = {
        "endpoints_file_count": _count(rd / "js" / "endpoints.txt"),
        "endpoints_sample": endpoints,
        "linkfinder_summary": {
            "api_routes": lf_sum.get("api_routes"),
            "web_routes": lf_sum.get("web_routes"),
            "static_assets": lf_sum.get("static_assets"),
        },
        "note": "API_ROUTE/WEB_ROUTE are surface candidates, not vulns.",
    }

    # GitHub exposure slice (Playbook §2-3)
    gh_sum = _load_json(rd / "github_exposure" / "summary.json") or {}
    gh_lines = _lines(rd / "js" / "github_exposure_slice.txt")[:CAP]
    sections["github_exposure_slice"] = {
        "summary": {
            "provider_status": gh_sum.get("provider_status"),
            "queries_run": gh_sum.get("queries_run"),
            "candidates_kept": gh_sum.get("candidates_kept"),
        },
        "sample": gh_lines,
        "note": "Playbook-aligned GitHub code search — LEAD only, never use secrets.",
    }

    # Derived probes (P1a)
    der_sum = _load_json(idir / "derived_probes_summary.json") or {}
    der_rows = _jsonl(idir / "derived_probes.jsonl", limit=100)
    der_hits = [
        r for r in der_rows
        if (r.get("disposition") == "CONTENT_SUPPORTED")
        or (r.get("kind") == "source_map" and (r.get("status") or 0) == 200)
    ][:CAP]
    sections["derived_probes"] = {
        "summary": der_sum,
        "content_supported_sample": der_hits,
        "note": "Stage-derived .map / backup siblings — LEAD/review only.",
    }

    # Pointers
    sections["pointers"] = {
        "GATE_0": "triage/GATE_0.md",
        "SECRETS_REVIEW": "triage/SECRETS_REVIEW.md",
        "EXPOSURE_QUEUE": "triage/EXPOSURE_QUEUE.md",
        "hunter_queue": "detection/hunter_queue.md",
        "smart_403": "detection/smart_403_summary.json",
        "plan": "docs/INFO_DISCLOSURE_EXECUTION_PLAN.md",
    }

    total_signalish = (
        sections["path_probes"]["total_hits"]
        + sections["secrets"]["secrets_high_count"]
        + sections["source_maps"]["count"]
        + len(strong)
        + (1 if sections["js_endpoints"]["endpoints_file_count"] else 0)
    )

    return {
        "schema": SCHEMA,
        "total_signalish_buckets": total_signalish,
        "sections": sections,
        "operator_en": (
            "Disclosure Desk aggregates existing recon signals for human review. "
            "Empty path probes with FUNNEL_OK does not mean the target is secure."
        ),
        "operator_ar": (
            "مكتب التسريب يجمع إشارات موجودة للمراجعة البشرية. "
            "مسارات فاضية مع FUNNEL_OK لا تعني أن الهدف آمن."
        ),
    }


def render_md(report: dict[str, Any]) -> str:
    s = report["sections"]
    lines = [
        "# DISCLOSURE_DESK — Information disclosure family",
        "",
        f"_{report.get('operator_en', '')}_",
        "",
        f"**AR:** {report.get('operator_ar', '')}",
        "",
        "## Open next",
        "",
    ]
    for k, v in (s.get("pointers") or {}).items():
        lines.append(f"- `{k}`: `{v}`")
    lines += ["", "---", "", "## 1) Path probes", ""]
    pc = s["path_probes"]["counts"]
    lines.append("| Kind | Count |")
    lines.append("|------|------:|")
    for k, n in pc.items():
        lines.append(f"| {k} | {n} |")
    lines.append("")
    lines.append(f"_{s['path_probes'].get('note', '')}_")
    lines.append("")
    for kind, samples in (s["path_probes"].get("samples") or {}).items():
        if not samples:
            continue
        lines.append(f"### {kind}")
        for row in samples[:15]:
            lines.append(f"- `{row[:200]}`")
        lines.append("")

    lines += ["## 2) Secrets", ""]
    sec = s["secrets"]
    lines.append(f"- **secrets_high count:** {sec['secrets_high_count']}")
    lines.append(f"- **Full review:** `{sec['full_review']}`")
    lines.append(f"- _{sec.get('note', '')}_")
    lines.append("")
    for row in sec.get("secrets_high_sample") or []:
        lines.append(f"- `{row[:180]}`")
    lines.append("")

    lines += ["## 3) Source maps", ""]
    sm = s["source_maps"]
    lines.append(f"- **count:** {sm['count']}")
    for row in sm.get("sample") or []:
        lines.append(f"- `{row[:180]}`")
    lines.append("")

    lines += ["## 4) GitHub recon (kept sample)", ""]
    gh = s["github_recon"]
    lines.append(f"- **sample size:** {len(gh.get('sample') or [])}")
    for row in gh.get("sample") or []:
        lines.append(f"- `{row[:180]}`")
    lines.append("")

    lines += ["## 5) Historical", ""]
    hist = s["historical"]
    piv = hist.get("pivot_summary") or {}
    val = hist.get("validation_summary") or {}
    if piv:
        lines.append(f"- pivot: `{json.dumps(piv.get('counts') or piv, ensure_ascii=False)[:300]}`")
    if val:
        lines.append(
            f"- validation: validated={val.get('validated')} outcomes={val.get('outcomes')} "
            f"budget={val.get('budget')}"
        )
    lines.append(f"- _{hist.get('note', '')}_")
    lines.append("")

    lines += ["## 6) Cloud exposure clues", ""]
    cloud = s["cloud"]
    summ = cloud.get("summary") or {}
    if summ:
        lines.append(
            f"- candidates={summ.get('candidates')} probes={summ.get('probes')} "
            f"by_disposition={summ.get('by_disposition')} auto_confirmed={summ.get('auto_confirmed')}"
        )
    for row in cloud.get("strong_clues_sample") or []:
        lines.append(
            f"- `{row.get('asset')}` · {row.get('provider')} · {row.get('disposition')}"
        )
    lines.append(f"- _{cloud.get('note', '')}_")
    lines.append("")

    lines += ["## 7) JS endpoints (LinkFinder materialization)", ""]
    js = s["js_endpoints"]
    lines.append(f"- endpoints.txt lines: {js.get('endpoints_file_count')}")
    lines.append(f"- linkfinder: {js.get('linkfinder_summary')}")
    for row in js.get("endpoints_sample") or []:
        lines.append(f"- `{row[:160]}`")
    lines.append(f"- _{js.get('note', '')}_")
    lines.append("")

    lines += ["## 8) GitHub exposure slice (Playbook)", ""]
    ghs = s.get("github_exposure_slice") or {}
    gs = ghs.get("summary") or {}
    lines.append(f"- provider_status={gs.get('provider_status')} queries={gs.get('queries_run')} kept={gs.get('candidates_kept')}")
    for row in ghs.get("sample") or []:
        lines.append(f"- `{row[:180]}`")
    lines.append(f"- _{ghs.get('note', '')}_")
    lines.append("")

    lines += ["## 9) Derived probes (JS→map / path→backup)", ""]
    der = s.get("derived_probes") or {}
    ds = der.get("summary") or {}
    if ds:
        lines.append(
            f"- probed={ds.get('probed')} map_hits={ds.get('map_hits')} "
            f"backup_content_hits={ds.get('backup_content_hits')} by_disposition={ds.get('by_disposition')}"
        )
    for row in der.get("content_supported_sample") or []:
        lines.append(f"- `{row.get('url','')[:160]}` · {row.get('kind')} · {row.get('disposition')}")
    lines.append(f"- _{der.get('note', '')}_")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Schema: `" + report.get("schema", SCHEMA) + "`. LEAD/review only — never CONFIRMED from this desk.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build triage/DISCLOSURE_DESK.md")
    ap.add_argument("--results-dir", required=True)
    args = ap.parse_args()
    rd = Path(args.results_dir)
    triage = rd / "triage"
    meta = rd / "meta"
    triage.mkdir(parents=True, exist_ok=True)
    meta.mkdir(parents=True, exist_ok=True)

    report = build(rd)
    (meta / "disclosure_desk.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (triage / "DISCLOSURE_DESK.md").write_text(render_md(report), encoding="utf-8")
    print(
        json.dumps(
            {
                "ok": True,
                "out": str(triage / "DISCLOSURE_DESK.md"),
                "signalish": report.get("total_signalish_buckets"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
