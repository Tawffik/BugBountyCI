#!/usr/bin/env python3
"""
smart_403_engine.py — Bounded adaptive 403/401 bypass checks for Zero Track.

Source: Notion "Smart 403 Bypass Framework" (adaptive techniques + baseline/404
calibration + FP reduction). Integration rules for BugBountyCI:

  - Only runs on already-observed 401/403 URLs (smart-fuzzing / access-control /
    live hints) — never whole-site fuzz.
  - Hard caps on endpoints and probes (CI-safe).
  - Scope filter via pipeline.scope.
  - Classification: LEAD max for a single interesting diff; never CONFIRMED.
  - Complements AccessControlEngine (path mutations on blocked baselines) and
    optional early WAF_BYPASS toggle (host-root header probes only).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

try:
    from pipeline.scope import in_scope_url, resolve_target_domain
except Exception:  # pragma: no cover
    def in_scope_url(u: str, t: Optional[str]) -> bool:  # type: ignore
        return True

    def resolve_target_domain(*a, **k):  # type: ignore
        return None

MAX_ENDPOINTS = 12
MAX_TECHNIQUES_PER_URL = 28
TIMEOUT = 8

# --- technique generators (lean subset of Notion framework) ---

HEADER_REWRITE = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "X-Forwarded-URI",
]
HEADER_IP = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "True-Client-IP",
]
IP_VALUES = ["127.0.0.1", "localhost", "::1"]
FAKE_EXT = [".js", ".css", ".json", ";.js", ";.css"]
AZURE_QUERY = ["?x=.js", "?x=.css", "?.js"]
END_SUFFIX = ["/", "/.", "/./", "/..;/", "%2f", "%00", "..;"]
MID_INSERT = ["/%2e/", "/./", "/;/", "/..;/"]


def _norm_url(u: str) -> str:
    u = (u or "").strip()
    if not u.startswith("http"):
        return ""
    try:
        p = urlparse(u)
        return urlunparse((p.scheme, p.netloc, p.path or "/", "", "", ""))
    except Exception:
        return u.split()[0]


def _fingerprint(headers: Dict[str, str], server: str) -> str:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    server_l = (server or "").lower()
    blob = str(h).lower()
    if "microsoft-azure-application-gateway" in server_l or "x-azure" in blob:
        return "azure"
    if "cf-ray" in h or "cloudflare" in server_l:
        return "cloudflare"
    if "nginx" in server_l:
        return "nginx"
    if "x-amz-cf-id" in h or "amazon" in server_l:
        return "aws"
    if "x-middleware" in blob or "next" in server_l:
        return "nextjs"
    return "unknown"


def _probe(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]],
    user_agent: str,
    timeout: int,
) -> Optional[Dict[str, Any]]:
    cmd = [
        "curl", "-sk", "--max-time", str(timeout), "-X", method,
        "-H", f"User-Agent: {user_agent}",
        "-D", "-", "-o", "/tmp/s403_body_$$", "-w", "\n%{http_code}",
        "--max-redirs", "0",
    ]
    # Use process substitution style via temp files for reliability
    body_path = f"/tmp/s403_body_{os.getpid()}_{hash(url) & 0xFFFF}"
    cmd = [
        "curl", "-sk", "--max-time", str(timeout), "-X", method,
        "-H", f"User-Agent: {user_agent}",
        "-D", "-", "-o", body_path, "-w", "\n%{http_code}",
        "--max-redirs", "0",
    ]
    for k, v in (headers or {}).items():
        cmd.extend(["-H", f"{k}: {v}"])
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        out = r.stdout or ""
        parts = out.rsplit("\n", 1)
        status_str = parts[-1].strip() if parts else ""
        if not status_str.isdigit():
            return None
        status = int(status_str)
        header_blob = parts[0] if len(parts) > 1 else ""
        body = b""
        if os.path.isfile(body_path):
            with open(body_path, "rb") as f:
                body = f.read()
            try:
                os.remove(body_path)
            except OSError:
                pass
        hdrs: Dict[str, str] = {}
        server = ""
        location = ""
        ctype = ""
        for line in header_blob.splitlines():
            if ":" in line and not line.lower().startswith("http/"):
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                hdrs[k] = v
                lk = k.lower()
                if lk == "server":
                    server = v
                elif lk == "location":
                    location = v
                elif lk == "content-type":
                    ctype = v
        return {
            "status": status,
            "length": len(body),
            "body_hash": hashlib.sha256(body[:4096]).hexdigest()[:16],
            "content_type": ctype,
            "location": location,
            "server": server,
            "headers": hdrs,
        }
    except Exception:
        return None


def is_interesting(baseline: Dict[str, Any], cand: Dict[str, Any], calib: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    if not cand or not baseline:
        return False, ""
    reasons: List[str] = []
    if cand["status"] == baseline["status"] and cand["body_hash"] == baseline["body_hash"]:
        return False, "identical to baseline"
    if cand["status"] != baseline["status"]:
        if cand["status"] in (200, 201, 202, 204, 301, 302, 307, 308, 401, 405):
            reasons.append(f"status {baseline['status']}→{cand['status']}")
        else:
            return False, "status not actionable"
    if calib and cand["status"] == calib.get("status") and abs(cand["length"] - calib.get("length", 0)) < 40:
        if cand["body_hash"] == calib.get("body_hash"):
            return False, "matches 404 calibration"
    if abs(cand["length"] - baseline["length"]) > 50:
        reasons.append(f"len_delta={cand['length'] - baseline['length']}")
    if cand.get("content_type") and baseline.get("content_type") and cand["content_type"] != baseline["content_type"]:
        reasons.append("content-type changed")
    loc = (cand.get("location") or "").lower()
    if any(x in loc for x in ("login", "signin", "sign-in", "auth", "forbidden", "denied")):
        return False, "redirect to auth/deny"
    if reasons:
        return True, ", ".join(reasons)
    # status same but body changed substantially
    if cand["body_hash"] != baseline["body_hash"] and abs(cand["length"] - baseline["length"]) > 80:
        return True, "body changed vs baseline"
    return False, ""


def gen_techniques(url: str, tech: str) -> List[Tuple[str, str, Dict[str, str], str]]:
    """Return list of (technique, method, headers, request_url)."""
    out: List[Tuple[str, str, Dict[str, str], str]] = []
    parsed = urlparse(url)
    path = parsed.path or "/"
    base = url.rstrip("/")
    root = f"{parsed.scheme}://{parsed.netloc}/"

    def add(name: str, method: str, u: str, headers: Optional[Dict[str, str]] = None):
        out.append((name, method, headers or {}, u))

    # Core high-value from Notion, ordered by adaptive profile
    def header_rewrite():
        for h in HEADER_REWRITE:
            add("header-rewrite", "GET", root, {h: path})
            add("header-rewrite", "GET", url, {h: path})

    def header_ip():
        for h in HEADER_IP:
            for v in IP_VALUES[:2]:
                add("header-ip", "GET", url, {h: v})

    def endpaths():
        for s in END_SUFFIX:
            add("endpath", "GET", base + s, None)

    def fake_ext():
        for e in FAKE_EXT:
            add("fake-ext", "GET", base + e, None)

    def azure_q():
        for q in AZURE_QUERY:
            add("azure-query", "GET", url + q, None)

    def midpaths():
        segs = [s for s in path.split("/") if s]
        if not segs:
            return
        last = segs[-1]
        prefix = "/" + "/".join(segs[:-1]) if len(segs) > 1 else ""
        for mid in MID_INSERT:
            add("midpath", "GET", f"{parsed.scheme}://{parsed.netloc}{prefix}{mid}{last}", None)

    def methods():
        for m in ("POST", "OPTIONS", "HEAD"):
            add(f"method-{m}", m, url, None)
        add("method-override", "GET", url, {"X-HTTP-Method-Override": "POST"})

    def char_encode():
        segs = path.rstrip("/").split("/")
        last = segs[-1] if segs else ""
        if last:
            enc = f"%{ord(last[0]):02x}" + last[1:]
            new_path = "/".join(segs[:-1] + [enc])
            add("char-encode", "GET", f"{parsed.scheme}://{parsed.netloc}/{new_path.lstrip('/')}", None)

    order = {
        "azure": [azure_q, header_ip, header_rewrite, endpaths, fake_ext, char_encode],
        "cloudflare": [fake_ext, char_encode, endpaths, header_rewrite, midpaths],
        "nginx": [midpaths, endpaths, header_rewrite, char_encode],
        "nextjs": [header_rewrite, methods, endpaths, fake_ext],
        "unknown": [header_rewrite, endpaths, fake_ext, midpaths, header_ip, methods, char_encode],
        "aws": [header_rewrite, header_ip, endpaths, fake_ext],
    }.get(tech, None) or [
        header_rewrite, endpaths, fake_ext, midpaths, header_ip, methods, char_encode
    ]
    for gen in order:
        gen()
        if len(out) >= MAX_TECHNIQUES_PER_URL:
            break
    return out[:MAX_TECHNIQUES_PER_URL]


def collect_blocked_urls(results_dir: str, target: Optional[str], limit: int) -> List[str]:
    found: List[str] = []
    seen = set()

    def add(u: str):
        u = _norm_url(u)
        if not u or u in seen:
            return
        if target and not in_scope_url(u, target):
            return
        seen.add(u)
        found.append(u)

    # smart-fuzzing response diffs with 401/403
    rd = os.path.join(results_dir, "smart-fuzzing", "response_diffs.json")
    if os.path.isfile(rd):
        try:
            data = json.load(open(rd, encoding="utf-8", errors="replace"))
            rows = data if isinstance(data, list) else data.get("diffs") or data.get("results") or []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                st = row.get("status") or row.get("status_code") or (row.get("response") or {}).get("status")
                try:
                    st_i = int(st)
                except Exception:
                    continue
                if st_i in (401, 403):
                    add(str(row.get("url") or row.get("target") or ""))
        except Exception:
            pass

    # engine_results access-control targets
    er = os.path.join(results_dir, "detection", "engine_results.json")
    if os.path.isfile(er):
        try:
            data = json.load(open(er, encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                data = [data]
            for eng in data or []:
                for ev in eng.get("evidence") or []:
                    t = (ev.get("candidate") or {}).get("target") or ""
                    add(str(t))
        except Exception:
            pass

    # interesting / admin-ish from hostname ranking
    for rel in ("live/hostname_targets.txt", "ai_infra/admin_panels.txt"):
        p = os.path.join(results_dir, rel)
        if not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                u = line.strip().split()[0] if line.strip() else ""
                if u.startswith("http") and any(x in u.lower() for x in ("admin", "internal", "manage", "dashboard", "api/")):
                    add(u)
                if len(found) >= limit * 3:
                    break

    return found[:limit]


def run_engine(
    results_dir: str,
    target: Optional[str] = None,
    user_agent: str = "Mozilla/5.0",
    max_endpoints: int = MAX_ENDPOINTS,
    timeout: int = TIMEOUT,
) -> Dict[str, Any]:
    target = target or resolve_target_domain(results_dir) or ""
    urls = collect_blocked_urls(results_dir, target or None, max_endpoints)
    out_dir = os.path.join(results_dir, "detection")
    os.makedirs(out_dir, exist_ok=True)
    findings_path = os.path.join(out_dir, "smart_403_findings.jsonl")
    summary_path = os.path.join(out_dir, "smart_403_summary.json")

    findings: List[Dict[str, Any]] = []
    stats = {
        "endpoints_selected": len(urls),
        "probes": 0,
        "leads": 0,
        "skipped_not_blocked": 0,
        "tech": {},
    }

    for url in urls:
        baseline = _probe("GET", url, None, user_agent, timeout)
        stats["probes"] += 1
        if not baseline:
            continue
        if baseline["status"] not in (401, 403):
            # Still allow if path was candidate but root-like 403 pages
            if baseline["status"] not in (401, 403, 404):
                stats["skipped_not_blocked"] += 1
                # only test if was expected blocked; skip open 200s
                if baseline["status"] < 400:
                    continue
        tech = _fingerprint(baseline.get("headers") or {}, baseline.get("server") or "")
        stats["tech"][tech] = stats["tech"].get(tech, 0) + 1
        parsed = urlparse(url)
        calib_url = f"{parsed.scheme}://{parsed.netloc}/thispathdoesnotexist404xyz123"
        calib = _probe("GET", calib_url, None, user_agent, timeout)
        stats["probes"] += 1

        for tech_name, method, headers, req_url in gen_techniques(url, tech):
            if target and not in_scope_url(req_url, target):
                continue
            cand = _probe(method, req_url, headers, user_agent, timeout)
            stats["probes"] += 1
            if not cand:
                continue
            ok, reason = is_interesting(baseline, cand, calib)
            if not ok:
                continue
            findings.append({
                "schema": "bugbountyci.smart_403.v1",
                "classification": "LEAD",
                "never_confirmed": True,
                "technique": tech_name,
                "tech_profile": tech,
                "target": url,
                "request_url": req_url,
                "method": method,
                "headers": headers,
                "baseline_status": baseline["status"],
                "candidate_status": cand["status"],
                "baseline_length": baseline["length"],
                "candidate_length": cand["length"],
                "reason": reason,
                "curl": _curl(method, req_url, headers),
                "limitations": "Single-run differential signal — not a confirmed bypass; human replay required",
            })
            stats["leads"] += 1

    with open(findings_path, "w", encoding="utf-8") as f:
        for row in findings:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    summary = {
        "schema": "bugbountyci.smart_403_summary.v1",
        "target_domain": target or "",
        "stats": stats,
        "findings": len(findings),
        "note": "LEAD only — Smart 403 is investigation signal, never CONFIRMED",
        "notion_source": "Smart 403 Bypass Framework — adaptive techniques + baseline/404 calibration",
    }
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")

    phase_dir = os.path.join(results_dir, "meta", "phases")
    os.makedirs(phase_dir, exist_ok=True)
    phase = {
        "phase": "smart_403",
        "status": "ok",
        "detail": f"endpoints={len(urls)} probes={stats['probes']} leads={stats['leads']}",
    }
    with open(os.path.join(phase_dir, "smart_403.json"), "w", encoding="utf-8") as f:
        json.dump(phase, f)
        f.write("\n")

    return summary


def _curl(method: str, url: str, headers: Dict[str, str]) -> str:
    parts = [f"curl -i -sS -k -X {method}"]
    for k, v in headers.items():
        parts.append(f"-H '{k}: {v}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description="Bounded Smart 403 phase for Zero Track")
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default="")
    ap.add_argument("--user-agent", default="Mozilla/5.0")
    ap.add_argument("--max-endpoints", type=int, default=MAX_ENDPOINTS)
    ap.add_argument("--timeout", type=int, default=TIMEOUT)
    args = ap.parse_args()
    summary = run_engine(
        args.results_dir,
        target=args.target or None,
        user_agent=args.user_agent,
        max_endpoints=args.max_endpoints,
        timeout=args.timeout,
    )
    print(f"✅ smart_403: findings={summary.get('findings')} stats={summary.get('stats')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
