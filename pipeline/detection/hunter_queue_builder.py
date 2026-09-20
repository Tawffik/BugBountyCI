#!/usr/bin/env python3
"""
pipeline/detection/hunter_queue_builder.py

The last piece of V1: instead of the researcher opening 3-4 separate
files (detection/hunter_queue_preview.txt, ai_agent/idor_findings.txt,
smart-fuzzing/interesting.txt) and cross-referencing them by hand, this
merges everything into one prioritized hunter_queue.md.

Priority order (highest first) — NOT vulnerability severity, this is
investigation priority per the project's own Signal Ranking rule:
  1. HIGH_SIGNAL / CONFIRMED  (from Access-Control / Open Redirect —
     stable, replay-verified)
  2. IDOR-CANDIDATE            (from the Phase 5 IDOR step — already its
     own distinct evidence class, kept separate from LEAD since it has
     its own methodology and disclaimer)
  3. LEAD                      (single-observation, not yet replay-
     verified, or replay was inconclusive)
  4. INTERESTING                (from smart-fuzzing/interesting.txt —
     weakest tier: a response-diff signal with no replay/verification
     step at all, the earliest and least-verified stage of the pipeline)

Every entry keeps the Golden Rule wording from its own source ("a
changed response is a signal, not a vulnerability" / IDOR's own
enumeration-not-confirmed disclaimer) — this file does not simplify or
strip those caveats away when merging.
"""
import argparse
import json
import os
import re

PRIORITY_ORDER = {"HIGH_SIGNAL": 0, "CONFIRMED": 0, "IDOR-CANDIDATE": 1, "LEAD": 2, "INTERESTING": 3}


def load_detection_evidence(results_dir):
    """From detection/engine_results.json — Access-Control + Open Redirect
    (and any future engine that plugs into the same framework)."""
    path = os.path.join(results_dir, "detection", "engine_results.json")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", errors="ignore") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    entries = []
    for engine_result in data:
        engine_name = engine_result.get("engine", "unknown-engine")
        for ev in engine_result.get("evidence", []):
            cls = ev.get("classification")
            if cls not in ("LEAD", "HIGH_SIGNAL", "CONFIRMED"):
                continue  # NOISE/UNKNOWN/DUPLICATE never reach the hunter queue
            entries.append({
                "priority_class": cls,
                "engine": engine_name,
                "target": ev.get("candidate", {}).get("target", "?"),
                "reason": ev.get("reason", ""),
                "stable": ev.get("stable"),
            })
    return entries


def load_idor_findings(results_dir):
    """From ai_agent/idor_findings.txt — the Phase 5 IDOR step's own
    line-based output. Format: '[IDOR-CANDIDATE] <url> | Status:.. | ...'
    parsed loosely since this predates the structured Evidence schema."""
    path = os.path.join(results_dir, "ai_agent", "idor_findings.txt")
    if not os.path.isfile(path):
        return []
    with open(path, "r", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip()]

    entries = []
    for line in lines:
        if not line.startswith("[IDOR-CANDIDATE]") and not line.startswith("[IDOR"):
            continue  # skip "No IDOR findings" placeholder line, or anything unexpected
        m = re.match(r"\[([\w-]+)\]\s*(\S+)\s*\|(.*)", line)
        if not m:
            continue
        entries.append({
            "priority_class": "IDOR-CANDIDATE",
            "engine": "idor-phase5",
            "target": m.group(2),
            "reason": m.group(3).strip(),
            "stable": None,
        })
    return entries


def load_smart_fuzzing_interesting(results_dir):
    """From smart-fuzzing/interesting.txt — response_diff.py's output.
    This is the weakest tier: no replay/verification step exists for it
    at all, unlike the detection engines above."""
    path = os.path.join(results_dir, "smart-fuzzing", "interesting.txt")
    if not os.path.isfile(path):
        return []
    with open(path, "r", errors="ignore") as f:
        content = f.read()

    entries = []
    # interesting.txt's own format: "<url> [<status>] <length> bytes\n  <reason>\n\n"
    blocks = [b.strip() for b in content.split("\n\n") if b.strip() and not b.startswith("#")]
    for block in blocks:
        lines = block.splitlines()
        if not lines:
            continue
        target = lines[0].strip()
        reason = lines[1].strip() if len(lines) > 1 else ""
        entries.append({
            "priority_class": "INTERESTING",
            "engine": "smart-fuzzing/response_diff",
            "target": target,
            "reason": reason,
            "stable": None,
        })
    return entries


def render_markdown(entries, target_name):
    entries_sorted = sorted(entries, key=lambda e: PRIORITY_ORDER.get(e["priority_class"], 99))

    lines = [
        "# Hunter Queue",
        "",
        f"Target: {target_name}" if target_name else "",
        "",
        "> A changed response is a signal, not a vulnerability. "
        "IDOR-CANDIDATE entries are enumeration evidence, not confirmed "
        "cross-user authorization bypasses. All entries need manual "
        "investigation before being treated as findings.",
        "",
    ]

    if not entries_sorted:
        lines.append("No signals reached the hunter queue threshold on this run.")
        return "\n".join(lines) + "\n"

    for i, e in enumerate(entries_sorted, 1):
        stable_note = ""
        if e["stable"] is True:
            stable_note = " (stable across replay)"
        elif e["stable"] is False:
            stable_note = " (unstable across replay — lower confidence)"

        lines += [
            f"## {i}. [{e['priority_class']}] {e['target']}{stable_note}",
            "",
            f"**Source engine:** {e['engine']}",
            "",
            f"**Evidence:** {e['reason']}",
            "",
            "**Suggested next step:** manual verification by a human researcher "
            "(with a second authorized account for any IDOR-CANDIDATE entry).",
            "",
            "---",
            "",
        ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default="")
    args = ap.parse_args()

    entries = (
        load_detection_evidence(args.results_dir)
        + load_idor_findings(args.results_dir)
        + load_smart_fuzzing_interesting(args.results_dir)
    )

    out_dir = os.path.join(args.results_dir, "detection")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "hunter_queue.md")
    with open(out_path, "w") as f:
        f.write(render_markdown(entries, args.target))

    counts = {}
    for e in entries:
        counts[e["priority_class"]] = counts.get(e["priority_class"], 0) + 1
    print(f"✅ hunter_queue.md written ({len(entries)} entries: {counts}) -> {out_path}")


if __name__ == "__main__":
    main()
