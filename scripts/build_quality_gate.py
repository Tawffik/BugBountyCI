#!/usr/bin/env python3
"""Workflow Quality Gate — aggregate honesty for operators.

Does NOT run tools. Reads existing meta/phases, url_sources_health,
engine_health, funnel_gate and writes a single pass/fail-style summary.

Contracts (BBCI):
  ERROR ≠ EMPTY · PARTIAL ≠ CLEAN · RATE_LIMIT ≠ no exposure
  SOURCE_FAILED passive ≠ clean target
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SCHEMA = "bugbountyci.quality_gate.v1"
CRITICAL = (
    "live_probe",
    "url_collection",
    "information_disclosure",
    "smart_fuzzing",
    "ssrf",
    "access_control",
    "port_scan",
)


def _load(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _phases(rd: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    d = rd / "meta" / "phases"
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.json")):
        j = _load(p)
        if j:
            name = str(j.get("phase") or p.stem)
            out[name] = j
    return out


def build(rd: Path) -> dict[str, Any]:
    phases = _phases(rd)
    eh = _load(rd / "meta" / "engine_health.json") or {}
    ush = _load(rd / "meta" / "url_sources_health.json") or {}
    fg = _load(rd / "meta" / "funnel_gate.json") or {}

    findings: list[dict[str, str]] = []
    blocks_clean = False

    for name in CRITICAL:
        ph = phases.get(name) or {}
        st = str(ph.get("status") or "").lower()
        if st in ("error", "partial"):
            blocks_clean = True
            findings.append(
                {
                    "severity": "high",
                    "code": f"phase_{st}",
                    "detail": f"{name} status={ph.get('status')} — {ph.get('detail', '')}",
                }
            )

    # Passive URL honesty
    sources = ush.get("sources") or {}
    for src, meta in sources.items():
        if not isinstance(meta, dict):
            continue
        st = str(meta.get("status") or "")
        detail = str(meta.get("detail") or "")
        if st == "SOURCE_FAILED":
            findings.append(
                {
                    "severity": "medium",
                    "code": "passive_source_failed",
                    "detail": f"{src}: {detail} (not evidence target is clean)",
                }
            )
        elif st == "SOURCE_EMPTY" and src in ("gau", "waymore", "wayback"):
            findings.append(
                {
                    "severity": "info",
                    "code": "passive_source_empty",
                    "detail": f"{src}: empty — do not treat as target-clean alone",
                }
            )

    # GitHub / provider rate limits
    gh = phases.get("github_exposure_slice") or phases.get("github_recon") or {}
    gst = str(gh.get("status") or "").lower()
    if "rate" in gst or "rate_limit" in str(gh.get("detail") or "").lower():
        findings.append(
            {
                "severity": "medium",
                "code": "provider_rate_limit",
                "detail": f"GitHub exposure: {gh.get('status')} {gh.get('detail', '')}",
            }
        )
    if (rd / "meta" / "github_exposure_rate_limited").is_file():
        findings.append(
            {
                "severity": "medium",
                "code": "provider_rate_limit",
                "detail": "github_exposure_rate_limited marker present",
            }
        )


    # Disclosure / dork / data-exposure family rollup (operator honesty)
    def _n_jsonl(path: Path) -> int:
        if not path.is_file():
            return 0
        try:
            return sum(1 for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip())
        except OSError:
            return 0

    gh_sum = _load(rd / "github_exposure" / "summary.json") or {}
    arch = _load(rd / "info_disclosure" / "archive_sensitive_summary.json") or {}
    der = _load(rd / "info_disclosure" / "derived_probes_summary.json") or {}
    id_phase = phases.get("information_disclosure") or {}
    arch_phase = phases.get("archive_sensitive_probe") or {}
    sm_n = 0
    smp = rd / "source_maps" / "found.txt"
    if smp.is_file():
        try:
            sm_n = sum(1 for ln in smp.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip())
        except OSError:
            sm_n = 0
    probe_n = _n_jsonl(rd / "info_disclosure" / "probe_results.jsonl")
    derived_n = int(der.get("count") or der.get("probed") or der.get("total") or _n_jsonl(rd / "info_disclosure" / "derived_probes.jsonl"))
    arch_n = int(arch.get("probed") or arch.get("count") or 0)
    arch_leads = int(arch.get("leads") or 0)
    if not arch_n and arch_phase:
        # detail may carry numbers
        pass
    gh_status = str(gh_sum.get("overall") or gh_sum.get("status") or (phases.get("github_exposure_slice") or {}).get("status") or "UNKNOWN")
    findings.append(
        {
            "severity": "info",
            "code": "disclosure_family_rollup",
            "detail": (
                f"info_probes={probe_n} derived={derived_n} source_maps={sm_n} "
                f"archive_probed={arch_n} archive_leads={arch_leads} "
                f"github={gh_status} info_phase={id_phase.get('status') or 'n/a'}"
            ),
        }
    )
    if gh_status.upper() in ("RATE_LIMIT", "ERROR") or "rate" in gh_status.lower():
        findings.append(
            {
                "severity": "medium",
                "code": "disclosure_github_provider",
                "detail": f"GitHub exposure status={gh_status} — empty candidates ≠ no public exposure",
            }
        )
    if probe_n == 0 and derived_n == 0 and arch_n == 0 and sm_n == 0:
        findings.append(
            {
                "severity": "info",
                "code": "disclosure_family_empty",
                "detail": "No disclosure-family probe rows yet — check ENABLE flags, URL harvest, and timing (archive early vs export)",
            }
        )

    overall_eh = str(eh.get("overall") or "")
    funnel = str(fg.get("verdict") or "UNKNOWN")

    # Smart fuzzing operator rollup
    sf_sum = _load(rd / "smart-fuzzing" / "operator_summary.json") or {}
    if sf_sum:
        findings.append(
            {
                "severity": "info",
                "code": "smart_fuzz_rollup",
                "detail": (
                    f"wordlist={sf_sum.get('wordlist_n')} wolf={sf_sum.get('wolf_status')}/"
                    f"{sf_sum.get('wolf_lines')} hosts={sf_sum.get('hosts_count')} "
                    f"src={sf_sum.get('hosts_source')} interesting={sf_sum.get('interesting_n')} "
                    f"state={sf_sum.get('pipeline_state')}"
                ),
            }
        )
        if sf_sum.get("wolf_status") in ("WOLF_UNAVAILABLE", "WOLF_EMPTY"):
            findings.append(
                {
                    "severity": "medium",
                    "code": "smart_fuzz_wolf_weak",
                    "detail": f"{sf_sum.get('wolf_status')}: tech wordlist layer thin (Intigriti company+tech+generic)",
                }
            )
        if (sf_sum.get("wordlist_n") or 0) < 30:
            findings.append(
                {
                    "severity": "medium",
                    "code": "smart_fuzz_thin_wordlist",
                    "detail": f"wordlist_n={sf_sum.get('wordlist_n')} — custom list may be too small for discovery",
                }
            )

    # Verdict
    if blocks_clean:
        verdict = "BLOCKED"
        operator = "Do not treat run as CLEAN. Fix critical phase errors/partials first."
    elif any(f["code"] == "passive_source_failed" for f in findings):
        verdict = "DEGRADED_SOURCES"
        operator = "Funnel may still be OK; passive harvest incomplete — check url_sources_health."
    elif any(f["code"] == "provider_rate_limit" for f in findings):
        verdict = "DEGRADED_PROVIDER"
        operator = "Provider throttled; empty GitHub leads ≠ no exposure."
    elif funnel in ("STARVED", "ERROR"):
        verdict = "FUNNEL_FAIL"
        operator = f"Funnel verdict={funnel}. Open GATE_0 before hunting."
    elif funnel == "PARTIAL":
        verdict = "PARTIAL"
        operator = "Partial funnel — review GATE_0 reasons; some stages thin."
    else:
        verdict = "PASS"
        operator = "No critical stage integrity failures detected from meta. Still review GATE_0."

    return {
        "schema": SCHEMA,
        "verdict": verdict,
        "operator": operator,
        "engine_health_overall": overall_eh,
        "funnel_verdict": funnel,
        "findings": findings,
        "phases_checked": {k: (phases.get(k) or {}).get("status") for k in CRITICAL},
        "blocks_clean": blocks_clean,
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# QUALITY_GATE — stage honesty",
        "",
        f"**Verdict:** `{report['verdict']}`",
        "",
        report.get("operator") or "",
        "",
        f"- engine_health.overall: `{report.get('engine_health_overall')}`",
        f"- funnel (GATE_0): `{report.get('funnel_verdict')}`",
        f"- blocks_clean: `{report.get('blocks_clean')}`",
        "",
        "## Findings",
        "",
    ]
    findings = report.get("findings") or []
    if not findings:
        lines.append("_No integrity findings from available meta._")
    else:
        for f in findings:
            lines.append(f"- **{f.get('severity')}** `{f.get('code')}` — {f.get('detail')}")
    lines += [
        "",
        "## Critical phases",
        "",
    ]
    for k, v in (report.get("phases_checked") or {}).items():
        lines.append(f"- `{k}`: `{v}`")
    lines += [
        "",
        "## Contracts",
        "",
        "- ERROR ≠ EMPTY · PARTIAL ≠ CLEAN",
        "- Passive SOURCE_FAILED/EMPTY ≠ target clean",
        "- Provider RATE_LIMIT ≠ no exposure",
        "- Smart fuzz thin/wolf weak ≠ target has no paths",
        "- This gate does not confirm vulnerabilities",
        "",
        "## Next",
        "",
        "1. `triage/DISCLOSURE_DESK.md` + `triage/EASY_WINS.md`",
        "2. `triage/GATE_0.md` / `triage/DELTA.md`",
        "3. `triage/SMART_DORK_BOARD.md` then Hunter",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    args = ap.parse_args()
    rd = Path(args.results_dir)
    triage = rd / "triage"
    meta = rd / "meta"
    triage.mkdir(parents=True, exist_ok=True)
    meta.mkdir(parents=True, exist_ok=True)
    report = build(rd)
    (meta / "quality_gate.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (triage / "QUALITY_GATE.md").write_text(render_md(report), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "out": str(triage / "QUALITY_GATE.md")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
