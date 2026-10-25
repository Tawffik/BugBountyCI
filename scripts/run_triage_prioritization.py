#!/usr/bin/env python3
"""Triage & prioritization for Zero Track (extracted from workflow).

Contract (Notion Fix Control Center P0):
  - Never mark CONFIRMED from file presence alone (source maps, backup paths,
    CORS, CMS, WAF headers, origin IP redirects, takeover fingerprints).
  - Buckets: observed / lead / validation_required — confirmed only reserved
    for future human-verified export (not auto-filled here).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, List, Tuple

SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}

# Cloudflare / common edge anycast — not origin
EDGE_IP_RE = re.compile(
    r"\b(?:"
    r"104\.1[6-9]\.\d+\.\d+|104\.2[0-7]\.\d+\.\d+|"  # CF
    r"172\.6[4-9]\.\d+\.\d+|172\.7[0-1]\.\d+\.\d+|"
    r"13\.\d+\.\d+\.\d+|3\.\d+\.\d+\.\d+"  # common AWS edge-ish noise for Host probes
    r")\b"
)


def rl(rd: Path, path: str) -> List[str]:
    p = rd / path
    if not p.is_file():
        return []
    try:
        return [l.strip() for l in p.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    except OSError:
        return []


def is_edge_ip_line(line: str) -> bool:
    return bool(EDGE_IP_RE.search(line))


def build(rd: Path) -> dict[str, Any]:
    # (rank, severity, category, detail, status)
    items: List[Tuple[int, str, str, str, str]] = []

    def add_lead(sev: str, cat: str, detail: str):
        items.append((SEV_RANK.get(sev, 0), sev, cat, detail, "lead"))

    def add_observed(sev: str, cat: str, detail: str):
        items.append((SEV_RANK.get(sev, 0), sev, cat, detail, "observed"))

    def add_validation_required(sev: str, cat: str, detail: str):
        items.append((SEV_RANK.get(sev, 0), sev, cat, detail, "validation_required"))

    # Info disclosure path hits → validation_required (need body proof), never confirmed
    for l in rl(rd, "info_disclosure/git_exposure.txt"):
        add_validation_required("high", "Git Exposure", l)
    for l in rl(rd, "info_disclosure/backup_files.txt"):
        add_validation_required("medium", "Backup File", l)
    for l in rl(rd, "info_disclosure/config_files.txt"):
        add_validation_required("high", "Config Exposure", l)
    for l in rl(rd, "info_disclosure/dir_listing.txt"):
        add_validation_required("medium", "Directory Listing", l)
    for l in rl(rd, "info_disclosure/error_disclosure.txt"):
        add_validation_required("medium", "Error Disclosure", l)

    # Source maps / stack fingerprints → observed only
    for l in rl(rd, "source_maps/found.txt"):
        add_observed("info", "Source Map", l)
    for l in rl(rd, "source_maps/endpoints.txt")[:50]:
        add_observed("info", "Source Map Endpoint", l)

    # WAF — never confirmed from status flip alone
    for l in rl(rd, "waf_bypass/bypass_results.txt"):
        add_lead("medium", "WAF Header Signal", l)
    for l in rl(rd, "waf_bypass/path_bypass.txt"):
        if l.startswith("[PATH-BYPASS]"):
            add_lead("medium", "WAF Path Signal", l)
        else:
            add_observed("info", "WAF Path Note", l)
    for l in rl(rd, "waf_bypass/ip_spoof_bypass.txt"):
        add_lead("medium", "WAF IP-Spoof Signal", l)
    for l in rl(rd, "waf_bypass/origin_bypass.txt"):
        if "CONFIRMED" in l or l.startswith("[ORIGIN-BYPASS"):
            # Treat legacy CONFIRMED label as lead; drop pure edge anycast noise to observed
            if is_edge_ip_line(l) or "redirect-only" in l:
                add_observed("info", "Origin IP Edge/Redirect", l)
            else:
                add_lead("medium", "Origin IP Signal", l)
        elif "redirect-only" in l or "content-differs" in l:
            add_observed("info", "Origin IP Note", l)
        else:
            add_observed("info", "Origin IP Note", l)
    for l in rl(rd, "waf_bypass/waf_fingerprint.txt"):
        add_observed("info", "WAF Fingerprint", l)

    # CORS / takeover fingerprints → lead at best
    for l in rl(rd, "cors/vulnerable.txt"):
        add_lead("medium", "CORS Signal", l)
    for l in rl(rd, "targeted/subzy_takeover.txt"):
        add_lead("high", "Takeover Fingerprint", l)
    for rel in ("nuclei/takeover.jsonl", "nuclei/takeover.txt"):
        for l in rl(rd, rel)[:30]:
            add_lead("high", "Takeover Fingerprint", l)

    # Secrets already have SECRETS_REVIEW — mirror high only as validation_required
    for l in rl(rd, "js/secrets_high.txt")[:40]:
        add_validation_required("high", "Secret Candidate", l[:500])

    # Sort
    items.sort(key=lambda x: (-x[0], x[2], x[3]))

    triage_dir = rd / "triage"
    triage_dir.mkdir(parents=True, exist_ok=True)

    findings_path = triage_dir / "findings.jsonl"
    leads_path = triage_dir / "leads.jsonl"
    seen: set[str] = set()
    n_confirmed = 0  # always 0 from auto path
    n_vr = n_lead = n_obs = 0

    with findings_path.open("w", encoding="utf-8") as ff, leads_path.open("w", encoding="utf-8") as lf:
        for rank, sev, cat, detail, status in items:
            dedupe = hashlib.sha256(f"{cat}|{sev}|{detail}".encode("utf-8", errors="ignore")).hexdigest()[:16]
            if dedupe in seen:
                continue
            seen.add(dedupe)
            rec = {
                "id": dedupe,
                "source": (cat.split()[0].lower() if cat else "unknown"),
                "type": cat,
                "severity": sev,
                "status": status,  # observed | lead | validation_required — never auto confirmed
                "confidence": "low" if status == "observed" else "medium",
                "evidence": detail[:2000],
                "dedupe_key": dedupe,
                "never_auto_confirmed": True,
            }
            if status == "validation_required":
                n_vr += 1
                ff.write(json.dumps(rec, ensure_ascii=False) + "\n")
            elif status == "lead":
                n_lead += 1
                lf.write(json.dumps(rec, ensure_ascii=False) + "\n")
            else:
                n_obs += 1
                lf.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # Operator markdown
    md_lines = [
        "# Triage — automated prioritization",
        "",
        "**Contract:** nothing here is CONFIRMED. Auto path never sets `status=confirmed`.",
        "",
        f"- validation_required (in findings.jsonl): **{n_vr}**",
        f"- lead / observed (in leads.jsonl): **{n_lead + n_obs}** (leads={n_lead}, observed={n_obs})",
        f"- auto confirmed: **{n_confirmed}**",
        "",
        "Prefer `triage/GATE_0.md`, `SECRETS_REVIEW`, `EXPOSURE_QUEUE`, and `detection/hunter_queue.md`.",
        "",
    ]
    (triage_dir / "triage.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    summary = {
        "schema": "bugbountyci.triage_summary.v1",
        "auto_confirmed": 0,
        "validation_required": n_vr,
        "leads": n_lead,
        "observed": n_obs,
        "note": "CONFIRMED is reserved for human verification — not emitted by this script",
    }
    (triage_dir / "triage_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    args = ap.parse_args()
    rd = Path(args.results_dir)
    summary = build(rd)
    print(
        f"✅ Triage: auto_confirmed={summary['auto_confirmed']} "
        f"validation_required={summary['validation_required']} "
        f"leads={summary['leads']} observed={summary['observed']} "
        f"-> triage/ (never auto CONFIRMED)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
