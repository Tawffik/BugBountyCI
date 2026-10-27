#!/usr/bin/env python3
"""RRP-3: Funnel gate summary — do not read empty findings as "target is secure".

Writes:
  triage/GATE_0.md
  meta/funnel_gate.json

Verdicts:
  FUNNEL_OK   — DNS/live/URLs look usable enough for downstream review
  PARTIAL     — some signal, some stages missing or thin
  STARVED     — upstream empty while a precursor had data (classic uro wipe)
  ERROR       — critical phase error or DNS failure signal
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SCHEMA = "bugbountyci.funnel_gate.v1"


def _count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        return sum(1 for _ in path.open(errors="ignore") if _.strip())
    except OSError:
        return 0


def _file_bytes(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _read_phase(results: Path, name: str) -> dict[str, Any] | None:
    p = results / "meta" / "phases" / f"{name}.json"
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError, ValueError):
        return {"status": "error", "detail": "malformed phase file"}


def _phase_bad(ph: dict[str, Any] | None) -> bool:
    if not ph:
        return False
    st = str(ph.get("status") or "").lower()
    return st in {"error", "partial"}


def build(results_dir: Path) -> dict[str, Any]:
    resolved = _count_lines(results_dir / "subdomains" / "resolved.txt")
    all_subs = _count_lines(results_dir / "subdomains" / "all_subs.txt")
    live_txt = _count_lines(results_dir / "live" / "live.txt")
    hostname_targets = _count_lines(results_dir / "live" / "hostname_targets.txt")
    urls_all_lines = _count_lines(results_dir / "urls" / "all.txt")
    urls_all_bytes = _file_bytes(results_dir / "urls" / "all.txt")
    wayback_lines = _count_lines(results_dir / "urls" / "wayback.txt")
    gau_lines = _count_lines(results_dir / "urls" / "gau.txt")
    js_files = _count_lines(results_dir / "js" / "files.txt")
    secrets_high = _count_lines(results_dir / "js" / "secrets_high.txt")
    ports_txt = _count_lines(results_dir / "live" / "ports.txt")
    asn_cidrs = _count_lines(results_dir / "subdomains" / "asn_cidrs.txt")
    asn_ips_file = _count_lines(results_dir / "subdomains" / "asn_ips.txt")

    # Resource caps: inventory vs promoted (do NOT treat lower live as ASN failure)
    caps: dict[str, Any] = {}
    caps_path = results_dir / "meta" / "resource_caps.json"
    if caps_path.is_file():
        try:
            caps = json.loads(caps_path.read_text(encoding="utf-8", errors="replace"))
            if not isinstance(caps, dict):
                caps = {}
        except (OSError, json.JSONDecodeError, ValueError):
            caps = {}
    asn_ips_available = int(caps.get("asn_ips_available") or asn_ips_file or 0)
    asn_ips_promoted = int(caps.get("asn_ips_promoted") or 0)
    asn_port_cap = caps.get("asn_port_ip_cap")
    ip_live_cap = caps.get("ip_live_cap")
    naabu_cap = caps.get("naabu_ip_cap")

    phases = {
        "live_probe": _read_phase(results_dir, "live_probe"),
        "url_collection": _read_phase(results_dir, "url_collection"),
        "information_disclosure": _read_phase(results_dir, "information_disclosure"),
        "dns": _read_phase(results_dir, "dns"),
        "asn_discovery": _read_phase(results_dir, "asn_discovery"),
        "port_scan": _read_phase(results_dir, "port_scan"),
    }

    dns_failed_flag = (results_dir / "meta" / "DNS_FAILED").is_file()
    skip_heavy = (results_dir / "meta" / "SKIP_HEAVY_SCAN").is_file()

    reasons: list[str] = []
    verdict = "FUNNEL_OK"

    if dns_failed_flag or (all_subs > 0 and resolved == 0):
        verdict = "ERROR"
        reasons.append(
            f"DNS starved or DNS_FAILED (all_subs={all_subs}, resolved={resolved})"
        )

    if _phase_bad(phases.get("live_probe")) or _phase_bad(phases.get("url_collection")):
        if verdict != "ERROR":
            verdict = "ERROR"
        reasons.append("critical phase status error/partial (live_probe or url_collection)")

    # Classic Superdrug #14 pattern: passive URLs exist, merged all.txt empty
    precursor_urls = wayback_lines + gau_lines
    if precursor_urls > 0 and urls_all_lines == 0 and urls_all_bytes == 0:
        verdict = "STARVED"
        reasons.append(
            f"urls/all.txt empty while wayback+gau={precursor_urls} "
            "(possible merge/uro wipe — downstream JS/secrets starved)"
        )

    if live_txt == 0 and all_subs > 0 and verdict == "FUNNEL_OK":
        verdict = "STARVED"
        reasons.append(f"no live hosts while all_subs={all_subs}")

    if skip_heavy:
        if verdict == "FUNNEL_OK":
            verdict = "PARTIAL"
        reasons.append("SKIP_HEAVY_SCAN set — heavy stages intentionally skipped")

    if verdict == "FUNNEL_OK" and (live_txt == 0 or urls_all_lines == 0):
        verdict = "PARTIAL"
        reasons.append(
            f"thin surface (live={live_txt}, urls_all={urls_all_lines}) — "
            "do not treat empty findings as full coverage"
        )

    if (
        asn_ips_available > 0
        and asn_ips_promoted >= 0
        and asn_ips_available > max(asn_ips_promoted, 1) * 2
    ):
        reasons.append(
            f"ASN inventory {asn_ips_available} IPs → promoted {asn_ips_promoted} under caps "
            f"(asn_port_ip_cap={asn_port_cap}, ip_live_cap={ip_live_cap}) — expected, not ASN failure"
        )

    if not reasons and verdict == "FUNNEL_OK":
        reasons.append("DNS/live/URL counts look usable for operator review")

    ar_msg = {
        "FUNNEL_OK": "القمع شغال بما يكفي للمراجعة — فاضي بعدها مش معناه تلقائي إن الهدف آمن 100%.",
        "PARTIAL": "تغطية جزئية — راجع GATE قبل ما تقول الهدف نظيف.",
        "STARVED": "المدخلات اتجوّعت (مثل URLs/live) — النتائج الفاضية مش دليل أمان.",
        "ERROR": "فشل في طبقة أساسية (DNS/phase) — لا تقرأ التقرير كـ clean target.",
    }.get(verdict, "")

    return {
        "schema": SCHEMA,
        "verdict": verdict,
        "reasons": reasons,
        "operator_ar": ar_msg,
        "operator_en": (
            "Empty findings must not be reported as a secure target when "
            f"verdict is {verdict}."
        ),
        "counts": {
            "all_subs": all_subs,
            "resolved": resolved,
            "live_txt": live_txt,
            "hostname_targets": hostname_targets,
            "urls_all_lines": urls_all_lines,
            "urls_all_bytes": urls_all_bytes,
            "wayback_lines": wayback_lines,
            "gau_lines": gau_lines,
            "js_files": js_files,
            "secrets_high": secrets_high,
            "ports_txt": ports_txt,
            "asn_cidrs": asn_cidrs,
            "asn_ips_file": asn_ips_file,
            "asn_ips_available": asn_ips_available,
            "asn_ips_promoted": asn_ips_promoted,
            "asn_port_ip_cap": asn_port_cap,
            "ip_live_cap": ip_live_cap,
            "naabu_ip_cap": naabu_cap,
        },
        "resource_caps": caps,
        "asn_note": (
            "ASN/CIDR inventory is intentionally larger than promoted live/ports. "
            "Lower live counts vs old runs usually mean resource_caps, not a failed asnmap."
        ),
        "flags": {
            "dns_failed": dns_failed_flag,
            "skip_heavy_scan": skip_heavy,
        },
        "phases_seen": {
            k: (v or {}).get("status") for k, v in phases.items() if v is not None
        },
    }


def render_md(report: dict[str, Any]) -> str:
    c = report["counts"]
    lines = [
        "# GATE_0 — Funnel integrity",
        "",
        f"**Verdict:** `{report['verdict']}`  ",
        "",
        f"{report.get('operator_ar', '')}",
        "",
        f"_{report.get('operator_en', '')}_",
        "",
        "## Counts",
        "",
        f"| Metric | Value |",
        f"|--------|------:|",
        f"| all_subs | {c['all_subs']} |",
        f"| resolved | {c['resolved']} |",
        f"| live.txt | {c['live_txt']} |",
        f"| hostname_targets | {c['hostname_targets']} |",
        f"| urls/all.txt lines | {c['urls_all_lines']} |",
        f"| urls/all.txt bytes | {c['urls_all_bytes']} |",
        f"| wayback lines | {c['wayback_lines']} |",
        f"| gau lines | {c['gau_lines']} |",
        f"| js/files | {c['js_files']} |",
        f"| secrets_high | {c['secrets_high']} |",
        f"| ports.txt | {c.get('ports_txt', 0)} |",
        "",
        "## ASN / CIDR vs caps (not a failure if inventory >> live)",
        "",
        f"| Metric | Value |",
        f"|--------|------:|",
        f"| asn_cidrs | {c.get('asn_cidrs', 0)} |",
        f"| asn_ips (file) | {c.get('asn_ips_file', 0)} |",
        f"| asn_ips_available | {c.get('asn_ips_available', 0)} |",
        f"| asn_ips_promoted | {c.get('asn_ips_promoted', 0)} |",
        f"| asn_port_ip_cap | {c.get('asn_port_ip_cap', '—')} |",
        f"| ip_live_cap | {c.get('ip_live_cap', '—')} |",
        f"| naabu_ip_cap | {c.get('naabu_ip_cap', '—')} |",
        "",
        f"_{report.get('asn_note', '')}_",
        "",
        "## Reasons",
        "",
    ]
    for r in report.get("reasons") or []:
        lines.append(f"- {r}")
    lines += ["", "## Flags", ""]
    for k, v in (report.get("flags") or {}).items():
        lines.append(f"- `{k}`: `{v}`")
    if report.get("phases_seen"):
        lines += ["", "## Phases seen", ""]
        for k, v in report["phases_seen"].items():
            lines.append(f"- `{k}`: `{v}`")
    lines += [
        "",
        "## Operator next",
        "",
        "- `triage/DISCLOSURE_DESK.md` — information-disclosure family rollup",
        "- `triage/SECRETS_REVIEW.md` / `triage/EXPOSURE_QUEUE.md`",
        "- `detection/hunter_queue.md`",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--out-dir", default="")
    args = ap.parse_args()
    results = Path(args.results_dir)
    triage = Path(args.out_dir) if args.out_dir else results / "triage"
    meta = results / "meta"
    triage.mkdir(parents=True, exist_ok=True)
    meta.mkdir(parents=True, exist_ok=True)

    report = build(results)
    (meta / "funnel_gate.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (triage / "GATE_0.md").write_text(render_md(report), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "out": str(triage / "GATE_0.md")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
