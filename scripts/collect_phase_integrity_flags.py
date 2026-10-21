#!/usr/bin/env python3
"""Collect critical-phase ERROR/PARTIAL flags for pipeline health.

Used by the Pipeline Health Report step so pipeline_health.md reflects
smart_fuzzing/access_control/ssrf/... failures — not only arjun/nuclei.
write_pipeline_exports.py also derives these independently; this keeps
the MD producer honest so #37 is not the only defense.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

CRITICAL_PHASES = (
    "smart_fuzzing",
    "information_disclosure",
    "ssrf",
    "open_redirect",
    "access_control",
    "port_scan",
    "live_probe",
    "url_collection",
    "arjun",
)


def collect_phase_integrity_flags(results_dir: str) -> list[str]:
    flags: list[str] = []
    phases = Path(results_dir) / "meta" / "phases"
    if not phases.is_dir():
        return flags
    for name in CRITICAL_PHASES:
        pj = phases / f"{name}.json"
        if not pj.is_file():
            continue
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError, ValueError):
            flags.append(
                f"⚠️ **{name} phase file malformed** — do not treat as clean empty."
            )
            continue
        if not isinstance(data, dict):
            flags.append(
                f"⚠️ **{name} phase file unexpected type** — do not treat as clean empty."
            )
            continue
        st = str(data.get("status") or "")
        stu = st.upper()
        if stu in ("ERROR", "PARTIAL") or st.lower() in ("error", "partial"):
            detail = data.get("detail") or ""
            flags.append(
                f"⚠️ **{name} phase={st}** — {detail}. "
                f"Do not treat this stage as EMPTY_VALID or complete."
            )
    for pj in sorted(phases.glob("*.json")):
        name = pj.stem
        if name in CRITICAL_PHASES:
            continue
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError, ValueError):
            flags.append(
                f"⚠️ **{name} phase file malformed** — do not treat as clean empty."
            )
            continue
        if not isinstance(data, dict):
            flags.append(
                f"⚠️ **{name} phase file unexpected type** — do not treat as clean empty."
            )
    return flags


def main() -> int:
    rd = sys.argv[1] if len(sys.argv) > 1 else ""
    if not rd:
        print("usage: collect_phase_integrity_flags.py <results_dir>", file=sys.stderr)
        return 2
    for f in collect_phase_integrity_flags(rd):
        print(f)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
