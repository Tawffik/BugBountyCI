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
from urllib.parse import urlparse

PRIORITY_ORDER = {"HIGH_SIGNAL": 0, "CONFIRMED": 0, "IDOR-CANDIDATE": 1, "LEAD": 2, "INTERESTING": 3}
# Within same priority_class, prefer research-dense engines over low-value noise.
ENGINE_TIER = {
    "ssrf-v1": 0,
    "access-control": 0,
    "open-redirect": 0,
    "linkfinder_api": 1,
    "smart-fuzzing/response_diff": 2,
    "representation_differential": 2,
    "historical_pivot": 4,
}


def _load_oob_confirmed_labels(results_dir):
    """Labels that OOB Check actually observed (not merely probed)."""
    confirmed = set()
    path = os.path.join(results_dir, "ai_agent", "oob_findings.txt")
    if not os.path.isfile(path):
        return confirmed
    try:
        with open(path, "r", errors="ignore") as f:
            text = f.read()
    except OSError:
        return confirmed
    for m in re.findall(r"\b([a-f0-9]{12})\b", text, re.I):
        confirmed.add(m.lower())
    return confirmed


def _annotate_oob_status(reason, details, confirmed_labels):
    """Clarify OOB probe vs confirmed using oob_findings.txt."""
    details = details or {}
    label = str(details.get("oob_label") or "").lower()
    if not label:
        return reason
    if label in confirmed_labels:
        if "OOB_CONFIRMED" not in reason:
            reason = reason + f"; OOB_CONFIRMED label={label}"
        return reason
    reason = reason.replace(
        "OOB callback registered",
        "OOB probe fired (not confirmed)",
    )
    if "OOB_NOT_SEEN" not in reason:
        reason = reason + f"; OOB_NOT_SEEN label={label} (differential-only until oob_findings matches)"
    return reason



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

    confirmed_labels = _load_oob_confirmed_labels(results_dir)
    entries = []
    for engine_result in data:
        engine_name = engine_result.get("engine", "unknown-engine")
        for ev in engine_result.get("evidence", []):
            cls = ev.get("classification")
            if cls not in ("LEAD", "HIGH_SIGNAL", "CONFIRMED"):
                continue  # NOISE/UNKNOWN/DUPLICATE never reach the hunter queue
            reason = _annotate_oob_status(
                ev.get("reason", "") or "",
                ev.get("details") or {},
                confirmed_labels,
            )
            entries.append({
                "priority_class": cls,
                "engine": engine_name,
                "target": ev.get("candidate", {}).get("target", "?"),
                "reason": reason,
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




def load_linkfinder_api_routes(results_dir, limit=25):
    """API_ROUTE rows from LinkFinder normalize → INTERESTING hunter seeds.

    Does NOT claim vulnerabilities. Surfaces JS-discovered API paths that
    would otherwise only live in js_deep/ and relationships (capital.com #133
    had 32 API routes with zero Hunter visibility beyond SSRF/historical).
    """
    path = os.path.join(results_dir, "js_deep", "linkfinder_normalized.jsonl")
    if not os.path.isfile(path):
        return []
    entries = []
    seen = set()
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if len(entries) >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("classification") != "API_ROUTE":
                continue
            ep = (rec.get("resolved_url") or rec.get("raw_value") or "").strip().rstrip("\\")
            if not ep or ep in seen:
                continue
            # skip obvious static leftovers
            if ep.lower().endswith((".js", ".css", ".map", ".mjs")):
                continue
            seen.add(ep)
            src = rec.get("source_js") or "linkfinder"
            entries.append({
                "priority_class": "INTERESTING",
                "engine": "linkfinder_api",
                "target": ep,
                "reason": (
                    f"JS-discovered API_ROUTE (source={src[:80]}). "
                    f"Surface candidate for auth/object/parameter analysis — not a vulnerability."
                ),
                "stable": None,
            })
    return entries


def _is_scheme_only_redirect(validation_url: str, location: str) -> bool:
    """True when redirect only upgrades http↔https (or :443) on same host+path.

    capital.com #134: all 40 REDIRECTED hunter entries were scheme-only 301s.
    Those remain valid evidence in historical_validations.jsonl but are low
    value as Hunter INTERESTING items relative to API/SSRF candidates.
    """
    if not validation_url or not location:
        return False
    try:
        a, b = urlparse(validation_url), urlparse(location)
    except Exception:
        return False
    host_a = (a.hostname or "").lower()
    host_b = (b.hostname or "").lower()
    if not host_a or host_a != host_b:
        return False
    path_a = (a.path or "/").rstrip("/") or "/"
    path_b = (b.path or "/").rstrip("/") or "/"
    if path_a != path_b:
        return False
    # same host+path; different scheme (or explicit :443 on https netloc) counts as scheme-only
    if a.scheme != b.scheme:
        return True
    return False

def load_historical_validations(results_dir):
    """Bounded historical path validation outcomes → hunter seeds.

    Only CURRENTLY_REACHABLE and REDIRECTED become INTERSTING/LEAD-style work
    items. CURRENTLY_UNREACHABLE / NOT_RUN / ERROR stay as evidence in
    historical_validations.jsonl and are NOT zero-finding claims.
    HISTORICAL_PATH_CURRENT_HOST is a candidate, not a dead endpoint.
    """
    path = os.path.join(results_dir, "info_disclosure", "historical_validations.jsonl")
    if not os.path.isfile(path):
        return []
    entries = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            outcome = row.get("outcome") or ""
            if outcome not in ("CURRENTLY_REACHABLE", "REDIRECTED"):
                continue
            vurl = row.get("validation_url") or row.get("historical_url") or ""
            if not vurl:
                continue
            status = row.get("status")
            loc = row.get("location") or ""
            # Keep scheme-only redirects out of Hunter (still in validations artifact)
            if outcome == "REDIRECTED" and _is_scheme_only_redirect(vurl, loc):
                continue
            reason = (
                f"historical path validated current {outcome}"
                f" (status={status}"
                + (f", location={loc[:80]}" if loc else "")
                + "). Evidence only — not a vulnerability. "
                f"source={row.get('historical_source') or 'archive'}; "
                f"ladder={row.get('evidence_ladder')}; "
                f"next={row.get('next_pivot')}"
            )
            entries.append({
                "priority_class": "INTERESTING",
                "engine": "historical_pivot",
                "target": f"{vurl} [{status}] ({outcome})",
                "reason": reason[:500],
                "stable": None,
            })
    return entries



def load_representation_diffs(results_dir):
    """MEANINGFUL representation differentials only → Hunter INTERESTING."""
    path = os.path.join(results_dir, "info_disclosure", "representation_diffs.jsonl")
    if not os.path.isfile(path):
        return []
    entries = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("outcome") != "MEANINGFUL_DIFFERENTIAL":
                continue
            url = row.get("url") or ""
            diff = row.get("differential") or {}
            signals = "; ".join(diff.get("signals") or [])[:200]
            sens = ",".join(diff.get("sensitive_keys") or [])[:80]
            reason = (
                f"representation differential (Accept html vs json). {signals}. "
                + (f"sensitive_keys_hint={sens}. " if sens else "")
                + "Evidence only — not a vulnerability. "
                f"ladder={row.get('evidence_ladder')}; next={row.get('next_pivot')}"
            )
            entries.append({
                "priority_class": "INTERESTING",
                "engine": "representation_differential",
                "target": url[:250],
                "reason": reason[:500],
                "stable": None,
            })
    return entries


def load_surface_context(results_dir):
    """Additive meta context. Never invents findings."""
    meta = os.path.join(results_dir, "meta")
    ctx = {"profile": None, "health": None, "clusters": None, "vocab_sample": []}
    for name, key in (("target_profile.json","profile"),("engine_health.json","health"),("response_clusters.json","clusters")):
        fp = os.path.join(meta, name)
        if os.path.isfile(fp):
            try:
                with open(fp, "r", errors="ignore") as f:
                    ctx[key] = json.load(f)
            except Exception:
                pass
    vp = os.path.join(meta, "vocabulary.json")
    if os.path.isfile(vp):
        try:
            with open(vp, "r", errors="ignore") as f:
                v = json.load(f)
            for term in (v.get("terms") or []):
                if not isinstance(term, dict):
                    continue
                if (term.get("category") or "").upper() in ("BUILD_NOISE", "GENERIC", "COMMON"):
                    continue
                w = term.get("term") or term.get("word")
                if w:
                    ctx["vocab_sample"].append(str(w)[:64])
                if len(ctx["vocab_sample"]) >= 12:
                    break
        except Exception:
            pass
    rank_path = os.path.join(results_dir, "smart-fuzzing", "response_ranking.json")
    if os.path.isfile(rank_path):
        try:
            with open(rank_path, "r", errors="ignore") as f:
                ctx["ranking"] = json.load(f)
        except Exception:
            pass
    return ctx


def render_markdown(entries, target_name, context=None):
    entries_sorted = sorted(
        entries,
        key=lambda e: (
            PRIORITY_ORDER.get(e["priority_class"], 99),
            ENGINE_TIER.get(e.get("engine") or "", 5),
            e.get("target") or "",
        ),
    )

    run_id = os.environ.get("GITHUB_RUN_ID") or os.environ.get("BBCI_RUN_ID") or ""
    engine_counts = {}
    for e in entries_sorted:
        eng = e.get("engine") or "unknown"
        engine_counts[eng] = engine_counts.get(eng, 0) + 1
    lines = [
        "# Hunter Queue",
        "",
        f"Target: {target_name}" if target_name else "",
        f"Run: {run_id}" if run_id else "",
        f"Entries: {len(entries_sorted)} (" + ", ".join(f"{k}={v}" for k, v in sorted(engine_counts.items())) + ")" if entries_sorted else "",
        "",
        "> A changed response is a signal, not a vulnerability. "
        "IDOR-CANDIDATE entries are enumeration evidence, not confirmed "
        "cross-user authorization bypasses. All entries need manual "
        "investigation before being treated as findings.",
        "> Scheme-only historical redirects (http→https same host/path) stay in "
        "historical_validations.jsonl and are not promoted to this queue.",
        "",
    ]

    if context:
        health = (context.get("health") or {})
        prof = (context.get("profile") or {})
        counts = prof.get("counts") or {}
        if health or counts:
            lines += ["## Target surface snapshot", ""]
            if health.get("overall"):
                lines.append(f"**Engine health:** {health.get('overall')}")
            parts = [f"{k}={counts[k]}" for k in ("live_hosts","ports","urls_modeled","endpoints_modeled","response_clusters","observations") if k in counts]
            if parts:
                lines.append("**Counts:** " + ", ".join(parts))
            lines += ["", ""]
        ranking = context.get("ranking") or {}
        if ranking.get("waf_dominated"):
            lines += ["## Adaptive note", "",
                      f"**WAF-dominated responses** ({ranking.get('counts', {})}). "
                      "Further generic path fuzzing may be low information gain.", "", ""]
        clusters = (context.get("clusters") or {}).get("clusters") or []
        if clusters:
            lines += ["## Response intelligence (clusters)", ""]
            for c in clusters[:8]:
                lines.append(f"- **{c.get('classification','?')}** (n={c.get('count',0)})")
            lines += ["", ""]
        vocab = context.get("vocab_sample") or []
        if vocab:
            lines += ["## Target vocabulary (sample)", "", ", ".join(f"`{x}`" for x in vocab), "", ""]

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
        + load_historical_validations(args.results_dir)
        + load_representation_diffs(args.results_dir)
        + load_linkfinder_api_routes(args.results_dir)
    )

    out_dir = os.path.join(args.results_dir, "detection")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "hunter_queue.md")
    context = load_surface_context(args.results_dir)
    with open(out_path, "w") as f:
        f.write(render_markdown(entries, args.target, context=context))

    counts = {}
    for e in entries:
        counts[e["priority_class"]] = counts.get(e["priority_class"], 0) + 1
    print(f"✅ hunter_queue.md written ({len(entries)} entries: {counts}) -> {out_path}")


if __name__ == "__main__":
    main()
