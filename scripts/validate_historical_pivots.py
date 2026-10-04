#!/usr/bin/env python3
"""
validate_historical_pivots.py — bounded current validation for HISTORICAL_PATH_CURRENT_HOST

Closes the loop:
  HISTORICAL_PATH_CURRENT_HOST
        → bounded GET (no fuzz, no crawl, no auth bypass)
        → evidence / negative evidence
        → info_disclosure/historical_validations.jsonl
        → Hunter Queue intake (via hunter_queue_builder)

HISTORICAL_PATH_CURRENT_HOST means: path seen in archive on a currently-known host,
but path was not in current URL corpus. It is NOT "dead endpoint" and NOT a vulnerability.

Outcomes: CURRENTLY_REACHABLE | CURRENTLY_UNREACHABLE | REDIRECTED |
          BLOCKED_OR_RATE_LIMITED | VALIDATION_ERROR | NOT_RUN
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse, urlunparse


DEFAULT_BUDGET = 40
TIMEOUT_S = 8
UA = os.environ.get("SCAN_USER_AGENT", "BugBountyCI-HistoricalValidate/1.0")


def path_key(u: str) -> str:
    try:
        p = urlparse(u)
        path = p.path or "/"
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        return path.lower()
    except Exception:
        return ""


def host_of(u: str) -> str:
    try:
        return (urlparse(u).hostname or "").lower()
    except Exception:
        return ""


def build_validation_url(historical_url: str, current_hosts: set[str]) -> str | None:
    """Prefer https://<current-matching-host><historical-path>."""
    try:
        p = urlparse(historical_url)
        path = p.path or "/"
        query = p.query
        host = (p.hostname or "").lower()
        if host not in current_hosts:
            # host relation was established at pivot time; still require match
            return None
        scheme = "https"
        netloc = host
        return urlunparse((scheme, netloc, path, "", query, ""))
    except Exception:
        return None


def fingerprint(body: bytes, content_type: str) -> str:
    sample = body[:2048] if body else b""
    h = hashlib.sha256(sample).hexdigest()[:16]
    return f"{content_type}|len={len(body)}|sha={h}"


def probe(url: str, timeout: int = TIMEOUT_S) -> dict:
    """Single GET, no redirect follow chain (urllib default may follow — disable)."""
    ctx = ssl.create_default_context()
    # authorized recon targets may use odd certs; still capture outcome
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": UA, "Accept": "*/*"},
    )
    # do not follow redirects automatically — use custom opener
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(65536)
            status = getattr(resp, "status", None) or resp.getcode()
            ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip()
            return {
                "status": int(status),
                "content_type": ctype,
                "body_len": len(body),
                "fingerprint": fingerprint(body, ctype),
                "location": resp.headers.get("Location") or "",
                "error": None,
            }
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(65536)
        except Exception:
            pass
        ctype = (e.headers.get("Content-Type") or "").split(";")[0].strip() if e.headers else ""
        loc = e.headers.get("Location") if e.headers else ""
        return {
            "status": int(e.code),
            "content_type": ctype,
            "body_len": len(body),
            "fingerprint": fingerprint(body, ctype),
            "location": loc or "",
            "error": None,
        }
    except Exception as e:
        return {
            "status": 0,
            "content_type": "",
            "body_len": 0,
            "fingerprint": "",
            "location": "",
            "error": type(e).__name__,
        }


def classify_outcome(probe_result: dict) -> str:
    if probe_result.get("error"):
        return "VALIDATION_ERROR"
    status = probe_result.get("status") or 0
    if status in (301, 302, 303, 307, 308):
        return "REDIRECTED"
    if status in (401, 403):
        # auth/policy boundary — not "unreachable", not clean
        return "BLOCKED_OR_RATE_LIMITED"
    if status == 429:
        return "BLOCKED_OR_RATE_LIMITED"
    if status == 404 or status == 410:
        return "CURRENTLY_UNREACHABLE"
    if 200 <= status < 300:
        return "CURRENTLY_REACHABLE"
    if status in (500, 502, 503, 504):
        return "VALIDATION_ERROR"
    if status == 0:
        return "VALIDATION_ERROR"
    # other 4xx
    if 400 <= status < 500:
        return "CURRENTLY_UNREACHABLE"
    return "VALIDATION_ERROR"


def load_current_urls(rd: str) -> set[str]:
    paths = set()
    for rel in ("urls/all.txt", "live/live.txt", "live/verified.txt"):
        p = os.path.join(rd, rel)
        if not os.path.isfile(p):
            continue
        with open(p, "r", errors="ignore") as f:
            for line in f:
                u = line.strip().split()[0] if line.strip() else ""
                if u.startswith("http"):
                    paths.add(path_key(u))
    return paths


def load_current_hosts(rd: str) -> set[str]:
    hosts = set()
    for rel in ("live/live.txt", "live/verified.txt", "urls/all.txt"):
        p = os.path.join(rd, rel)
        if not os.path.isfile(p):
            continue
        with open(p, "r", errors="ignore") as f:
            for line in f:
                u = line.strip().split()[0] if line.strip() else ""
                h = host_of(u)
                if h:
                    hosts.add(h)
    return hosts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default="")
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    ap.add_argument("--dry-run", action="store_true", help="classify without HTTP")
    args = ap.parse_args()
    rd = args.results_dir
    out_dir = os.path.join(rd, "info_disclosure")
    os.makedirs(out_dir, exist_ok=True)

    pivots_path = os.path.join(out_dir, "historical_pivots.jsonl")
    pivots = []
    if os.path.isfile(pivots_path):
        with open(pivots_path, "r", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    pivots.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    eligible = [p for p in pivots if p.get("classification") == "HISTORICAL_PATH_CURRENT_HOST"]
    current_paths = load_current_urls(rd)
    current_hosts = load_current_hosts(rd)

    results = []
    stats = {
        "eligible": len(eligible),
        "already_known": 0,
        "deduped": 0,
        "validated": 0,
        "not_run": 0,
        "outcomes": {},
    }
    seen_validation_urls = set()
    budget_left = max(0, args.budget)

    for piv in eligible:
        hist_url = piv.get("url") or ""
        pk = piv.get("path") or path_key(hist_url)
        # already in current corpus → attach provenance only, no request
        if pk and pk in current_paths:
            stats["already_known"] += 1
            results.append({
                "schema": "bugbountyci.historical_validation.v1",
                "source": "historical_pivot",
                "historical_url": hist_url[:300],
                "historical_path": pk[:200],
                "historical_source": piv.get("historical_source"),
                "validation_url": None,
                "outcome": "NOT_RUN",
                "not_run_reason": "already_in_current_url_corpus",
                "status": None,
                "content_type": None,
                "fingerprint": None,
                "location": None,
                "evidence_ladder": "CORRELATED",
                "confidence": "medium",
                "next_pivot": "none_already_current",
                "limitations": "path already present in current corpus; no duplicate validation",
                "provenance": "info_disclosure/historical_pivots.jsonl",
            })
            continue

        vurl = build_validation_url(hist_url, current_hosts)
        if not vurl:
            stats["not_run"] += 1
            results.append({
                "schema": "bugbountyci.historical_validation.v1",
                "source": "historical_pivot",
                "historical_url": hist_url[:300],
                "historical_path": pk[:200],
                "validation_url": None,
                "outcome": "NOT_RUN",
                "not_run_reason": "host_not_in_current_hosts",
                "evidence_ladder": "CORRELATED",
                "confidence": "low",
                "next_pivot": "none",
                "limitations": "cannot build in-scope validation URL",
                "provenance": "info_disclosure/historical_pivots.jsonl",
            })
            continue

        if vurl in seen_validation_urls:
            stats["deduped"] += 1
            results.append({
                "schema": "bugbountyci.historical_validation.v1",
                "source": "historical_pivot",
                "historical_url": hist_url[:300],
                "historical_path": pk[:200],
                "validation_url": vurl[:300],
                "outcome": "NOT_RUN",
                "not_run_reason": "duplicate_validation_url",
                "evidence_ladder": "CORRELATED",
                "confidence": "low",
                "next_pivot": "none",
                "limitations": "deduplicated against earlier validation in this run",
                "provenance": "info_disclosure/historical_pivots.jsonl",
            })
            continue
        seen_validation_urls.add(vurl)

        if budget_left <= 0:
            stats["not_run"] += 1
            results.append({
                "schema": "bugbountyci.historical_validation.v1",
                "source": "historical_pivot",
                "historical_url": hist_url[:300],
                "historical_path": pk[:200],
                "validation_url": vurl[:300],
                "outcome": "NOT_RUN",
                "not_run_reason": "budget_exhausted",
                "evidence_ladder": "CORRELATED",
                "confidence": "low",
                "next_pivot": "none",
                "limitations": f"request budget {args.budget} exhausted",
                "provenance": "info_disclosure/historical_pivots.jsonl",
            })
            continue

        if args.dry_run:
            outcome = "NOT_RUN"
            pr = {"status": None, "content_type": None, "fingerprint": None, "location": None, "error": "dry_run"}
            not_run_reason = "dry_run"
        else:
            pr = probe(vurl)
            outcome = classify_outcome(pr)
            not_run_reason = None
            budget_left -= 1
            stats["validated"] += 1
            time.sleep(0.15)

        stats["outcomes"][outcome] = stats["outcomes"].get(outcome, 0) + 1

        # Hunter-worthy: reachable or interesting redirect — still not a vulnerability
        if outcome == "CURRENTLY_REACHABLE":
            ladder, conf, nxt = "CANDIDATE", "medium", "manual_review_content"
        elif outcome == "REDIRECTED":
            ladder, conf, nxt = "CANDIDATE", "low", "inspect_redirect_destination"
        elif outcome == "BLOCKED_OR_RATE_LIMITED":
            ladder, conf, nxt = "OBSERVED", "low", "none_auth_or_policy_boundary"
        elif outcome == "CURRENTLY_UNREACHABLE":
            ladder, conf, nxt = "OBSERVED", "low", "none_negative_evidence"
        elif outcome == "VALIDATION_ERROR":
            ladder, conf, nxt = "OBSERVED", "low", "none_infra_failure"
        else:
            ladder, conf, nxt = "CORRELATED", "low", "none"

        results.append({
            "schema": "bugbountyci.historical_validation.v1",
            "source": "historical_pivot",
            "historical_url": hist_url[:300],
            "historical_path": pk[:200],
            "historical_source": piv.get("historical_source"),
            "validation_url": vurl[:300],
            "outcome": outcome,
            "not_run_reason": not_run_reason,
            "status": pr.get("status"),
            "content_type": pr.get("content_type"),
            "fingerprint": pr.get("fingerprint"),
            "location": (pr.get("location") or "")[:200],
            "error": pr.get("error"),
            "evidence_ladder": ladder,
            "confidence": conf,
            "next_pivot": nxt,
            "limitations": (
                "current reachability is evidence only — not a vulnerability claim; "
                "historical path was missing from current URL corpus at pivot time"
            ),
            "provenance": "info_disclosure/historical_pivots.jsonl+bounded_get",
        })

    out_path = os.path.join(out_dir, "historical_validations.jsonl")
    with open(out_path, "w") as f:
        for row in results:
            f.write(json.dumps(row) + "\n")

    summary = {
        "schema": "bugbountyci.historical_validation_summary.v1",
        "eligible_historical_path_current_host": stats["eligible"],
        "already_known": stats["already_known"],
        "deduped": stats["deduped"],
        "validated": stats["validated"],
        "not_run": stats["not_run"] + sum(1 for r in results if r.get("outcome") == "NOT_RUN"),
        "outcomes": stats["outcomes"],
        "budget": args.budget,
        "note": "HISTORICAL_PATH_CURRENT_HOST is a candidate for validation, not a dead endpoint or vulnerability",
    }
    # recount not_run accurately
    summary["not_run"] = sum(1 for r in results if r.get("outcome") == "NOT_RUN")
    with open(os.path.join(out_dir, "historical_validation_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")

    print(
        f"✅ historical validation: eligible={stats['eligible']} "
        f"validated={stats['validated']} already_known={stats['already_known']} "
        f"deduped={stats['deduped']} outcomes={stats['outcomes']}"
    )


if __name__ == "__main__":
    main()
