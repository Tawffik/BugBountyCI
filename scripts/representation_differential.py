#!/usr/bin/env python3
"""
representation_differential.py — intelligence-driven representation comparison

Same resource → baseline GET → alternate Accept / known alternate path
→ compare → evidence (NOT automatically a vulnerability).

Uses existing target evidence for candidate selection (API-looking paths,
endpoints, JS relationships). Does NOT:
  - append .json to the whole URL corpus
  - create a second response_diff / fuzzing engine
  - recurse or crawl

Outputs:
  info_disclosure/representation_diffs.jsonl
  info_disclosure/representation_summary.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

DEFAULT_BUDGET = 25  # pairs ≈ up to 50 GETs
TIMEOUT_S = 8
UA = os.environ.get("SCAN_USER_AGENT", "BugBountyCI-RepDiff/1.0")

API_HINT = re.compile(
    # Path-segment oriented — avoid font false positives (/figtree/v9/...)
    r"(?:/api(?:/|$|\?)|/graphql(?:/|$|\?)|/rest(?:/|$|\?)"
    r"|/v\d+/(?:[A-Za-z_])"
    r"|/(?:export|download|users|profile|account|admin)(?:/|$|\?))",
    re.I,
)
SENSITIVE_KEY = re.compile(
    r"(email|phone|ssn|password|token|secret|internal|role|permission|billing|salary|ssn|address|dob)",
    re.I,
)


def probe(url: str, accept: str) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    req = urllib.request.Request(
        url, method="GET",
        headers={"User-Agent": UA, "Accept": accept},
    )
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=TIMEOUT_S) as resp:
            body = resp.read(65536)
            status = getattr(resp, "status", None) or resp.getcode()
            ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip()
            return _pack(int(status), ctype, body, None)
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(65536)
        except Exception:
            pass
        ctype = (e.headers.get("Content-Type") or "").split(";")[0].strip() if e.headers else ""
        return _pack(int(e.code), ctype, body, None)
    except Exception as e:
        return _pack(0, "", b"", type(e).__name__)


def _pack(status, ctype, body, error):
    sample = body[:2048] if body else b""
    fp = hashlib.sha256(sample).hexdigest()[:16]
    keys = []
    if body and ("json" in (ctype or "") or (body[:1] in (b"{", b"["))):
        try:
            data = json.loads(body.decode("utf-8", errors="ignore"))
            if isinstance(data, dict):
                keys = sorted(str(k) for k in data.keys())[:40]
            elif isinstance(data, list) and data and isinstance(data[0], dict):
                keys = sorted(str(k) for k in data[0].keys())[:40]
        except Exception:
            pass
    return {
        "status": status,
        "content_type": ctype,
        "body_len": len(body) if body else 0,
        "fingerprint": f"{ctype}|{len(body) if body else 0}|{fp}",
        "json_keys": keys,
        "error": error,
    }



def _is_api_hostname(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    if not h:
        return False
    first = h.split(".")[0]
    return first in ("api", "graphql", "rest") or first.startswith("api-")


def _bind_hosts(allowed: set[str], target: str) -> list:
    """Ordered in-scope hosts for relative path binding (prefer target, skip raw IPs)."""
    ordered = []
    seen = set()

    def push(h: str):
        h = (h or "").lower().rstrip(".")
        if not h or h in seen:
            return
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", h):
            return
        seen.add(h)
        ordered.append(h)

    t = (target or "").lower().strip().lstrip("*.")
    if t:
        push(t)
        push("www." + t)
        push("api." + t)
        push("app." + t)
    for h in sorted(allowed):
        push(h)
    return ordered


def in_scope_host(u: str, allowed_hosts: set[str]) -> bool:
    """Only same registrable target hosts (no external google/cdn leakage)."""
    if not allowed_hosts:
        return True
    try:
        h = (urlparse(u).hostname or "").lower()
    except Exception:
        return False
    if not h:
        return False
    if h in allowed_hosts:
        return True
    # subdomain of allowed host
    for ah in allowed_hosts:
        if h.endswith("." + ah) or ah.endswith("." + h):
            return True
    return False


def select_candidates(rd: str, cap: int = 40, target: str = "") -> list:
    """Intelligence-driven: API-looking paths from existing artifacts only."""
    seen = set()
    out = []
    allowed = set()
    if target:
        t = target.lower().strip().lstrip("*.")
        if t:
            allowed.add(t)
            allowed.add("www." + t)
            allowed.add("api." + t)
            allowed.add("app." + t)
    # also collect from live hosts
    for rel in ("live/live.txt", "live/verified.txt"):
        lp = os.path.join(rd, rel)
        if os.path.isfile(lp):
            with open(lp, "r", errors="ignore") as f:
                for line in f:
                    u = line.strip().split()[0] if line.strip() else ""
                    if u.startswith("http"):
                        try:
                            h = (urlparse(u).hostname or "").lower()
                            if h:
                                allowed.add(h)
                        except Exception:
                            pass

    def add(u: str, reason: str):
        u = u.strip().split()[0] if u.strip() else ""
        if not u.startswith("http"):
            return
        # Dedupe by scheme-agnostic host+path+query
        try:
            pu = urlparse(u)
            dedupe_key = (pu.hostname or "", pu.path or "/", pu.query or "")
        except Exception:
            dedupe_key = (u,)
        if dedupe_key in seen or u in seen:
            return
        if not in_scope_host(u, allowed):
            return
        # skip static assets + discovery noise (not Accept-representation surfaces)
        if re.search(r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|map|mp4|xml|txt)(\?|$)", u, re.I):
            return
        path = urlparse(u).path or "/"
        if re.search(r"^/(robots\.txt|sitemap\.xml|favicon\.ico|.*\.xml)$", path, re.I):
            return
        if "/.well-known/" in path.lower():
            return
        host = (urlparse(u).hostname or "").lower()
        api_path = bool(API_HINT.search(path))
        api_host = _is_api_hostname(host)
        # Bare roots only when host itself is an API host (api.target)
        if not api_path and not api_host and path in ("/", ""):
            return
        # api hostname alone must not promote robots/sitemap-style noise (already filtered)
        # non-API paths need meaningful depth from endpoint evidence
        if not api_path and not api_host:
            if path.count("/") < 2:
                return
        seen.add(dedupe_key)
        seen.add(u)
        # Prefer https when adding
        out.append({"url": u, "reason_selected": reason})

    def _ingest_endpoint_path(path: str, source: str) -> None:
        path = (path or "").strip()
        if not path:
            return
        if path.startswith("http"):
            # Prefer https form for http candidates of same host+path (dedupe handles rest)
            if path.startswith("http://"):
                add("https://" + path[len("http://"):], source)
            add(path, source)
        elif path.startswith("/") and API_HINT.search(path):
            for h in _bind_hosts(allowed, target):
                for scheme in ("https", "http"):
                    add(f"{scheme}://{h}{path}", f"{source}+hostbind")
                    if len(out) >= cap:
                        return

    # Primary: parameter_intelligence.json (exists before write_pipeline_exports)
    pi = os.path.join(rd, "detection", "parameter_intelligence.json")
    if os.path.isfile(pi):
        try:
            with open(pi, "r", errors="ignore") as f:
                pi_data = json.load(f)
            for row in pi_data.get("endpoints") or []:
                if isinstance(row, dict):
                    _ingest_endpoint_path(row.get("endpoint") or "", "detection/parameter_intelligence.json")
                if len(out) >= cap:
                    break
        except (json.JSONDecodeError, OSError):
            pass

    # Secondary: meta/endpoints.jsonl (written later by write_pipeline_exports)
    ep = os.path.join(rd, "meta", "endpoints.jsonl")
    if os.path.isfile(ep):
        with open(ep, "r", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                _ingest_endpoint_path(row.get("endpoint") or "", "meta/endpoints.jsonl")
                if len(out) >= cap:
                    break

    # urls/all.txt API-looking
    for rel in ("urls/api_urls.txt", "urls/all.txt", "js_deep/linkfinder_endpoints.txt", "js/linkfinder_endpoints.txt"):
        p = os.path.join(rd, rel)
        if not os.path.isfile(p):
            continue
        with open(p, "r", errors="ignore") as f:
            for i, line in enumerate(f):
                if i > 8000:
                    break
                u = line.strip().split()[0] if line.strip() else ""
                if not u:
                    continue
                if u.startswith("http") and (
                    API_HINT.search(urlparse(u).path or "")
                    or API_HINT.search(u)
                    or _is_api_hostname(urlparse(u).hostname or "")
                ):
                    add(u, rel)
                elif u.startswith("/") and API_HINT.search(u):
                    for h in _bind_hosts(allowed, target):
                        for scheme in ("https", "http"):
                            add(f"{scheme}://{h}{u}", f"{rel}+hostbind")
                            if len(out) >= cap:
                                return out[:cap]
                if len(out) >= cap:
                    break
    # Prefer https URL when both schemes present for same host+path
    preferred = []
    seen_hp = set()
    # pass1 https
    for item in out:
        pu = urlparse(item["url"])
        key = ((pu.hostname or ""), (pu.path or "/"), (pu.query or ""))
        if pu.scheme == "https" and key not in seen_hp:
            seen_hp.add(key)
            preferred.append(item)
    for item in out:
        pu = urlparse(item["url"])
        key = ((pu.hostname or ""), (pu.path or "/"), (pu.query or ""))
        if key not in seen_hp:
            seen_hp.add(key)
            preferred.append(item)
    return preferred[:cap]


def compare(base: dict, alt: dict) -> dict:
    """Return differential summary; never claims vulnerability."""
    signals = []
    if base.get("error") or alt.get("error"):
        return {"kind": "VALIDATION_ERROR", "signals": [], "sensitive_keys": [], "meaningful": False}
    if base.get("status") != alt.get("status"):
        signals.append(f"status {base.get('status')} vs {alt.get('status')}")
    bct = (base.get("content_type") or "").lower()
    act = (alt.get("content_type") or "").lower()
    if bct != act:
        signals.append(f"content-type {bct or '?'} vs {act or '?'}")
    bk = set(base.get("json_keys") or [])
    ak = set(alt.get("json_keys") or [])
    only_alt = sorted(ak - bk)
    only_base = sorted(bk - ak)
    if only_alt:
        signals.append(f"json_keys only_in_alt={only_alt[:12]}")
    if only_base:
        signals.append(f"json_keys only_in_base={only_base[:12]}")
    if base.get("fingerprint") != alt.get("fingerprint") and not signals:
        signals.append("body_fingerprint_differs")

    sens = [k for k in only_alt if SENSITIVE_KEY.search(k)]
    # Meaningful = more than trivial HTML vs empty, with field expansion or status+json
    meaningful = bool(sens) or (
        bool(only_alt)
        and "json" in act
        and base.get("status") == 200
        and alt.get("status") == 200
    ) or (
        base.get("status") != alt.get("status")
        and alt.get("status") == 200
        and "json" in act
    )

    if not signals:
        kind = "SAME_REPRESENTATION"
    elif meaningful:
        kind = "MEANINGFUL_DIFFERENTIAL"
    else:
        kind = "OBSERVED_DIFFERENTIAL"

    return {
        "kind": kind,
        "signals": signals,
        "sensitive_keys": sens[:10],
        "keys_only_in_alt": only_alt[:20],
        "meaningful": meaningful,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default="")
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    rd = args.results_dir
    out_dir = os.path.join(rd, "info_disclosure")
    os.makedirs(out_dir, exist_ok=True)

    candidates = select_candidates(rd, cap=max(args.budget, 10), target=args.target)
    results = []
    stats = {
        "candidates": len(candidates),
        "pairs_run": 0,
        "not_run": 0,
        "kinds": {},
    }
    budget = args.budget

    for cand in candidates:
        if budget <= 0:
            stats["not_run"] += 1
            results.append({
                "schema": "bugbountyci.representation_diff.v1",
                "url": cand["url"][:300],
                "outcome": "NOT_RUN",
                "not_run_reason": "budget_exhausted",
                "evidence_ladder": "OBSERVED",
                "confidence": "low",
                "limitations": "request budget exhausted",
                "provenance": cand.get("reason_selected"),
            })
            continue

        url = cand["url"]
        if args.dry_run:
            results.append({
                "schema": "bugbountyci.representation_diff.v1",
                "url": url[:300],
                "outcome": "NOT_RUN",
                "not_run_reason": "dry_run",
                "reason_selected": cand.get("reason_selected"),
                "evidence_ladder": "OBSERVED",
                "confidence": "low",
                "provenance": cand.get("reason_selected"),
            })
            stats["not_run"] += 1
            continue

        base = probe(url, "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
        alt = probe(url, "application/json, text/json;q=0.9, */*;q=0.1")
        budget -= 1
        stats["pairs_run"] += 1
        time.sleep(0.12)

        if base.get("error") and alt.get("error"):
            transport = {base.get("error"), alt.get("error")}
            net_errs = {"URLError", "TimeoutError", "socket.timeout", "ConnectionResetError", "OSError"}
            if transport & net_errs or any(
                (base.get("error") or "").endswith("Error") and (base.get("status") or 0) == 0
                for _ in (0,)
            ):
                outcome = "NETWORK_ERROR"
                diff = {
                    "kind": "NETWORK_ERROR",
                    "signals": [f"transport base={base.get('error')} alt={alt.get('error')}"],
                    "sensitive_keys": [],
                    "meaningful": False,
                }
            else:
                outcome = "VALIDATION_ERROR"
                diff = {"kind": "VALIDATION_ERROR", "signals": [], "sensitive_keys": [], "meaningful": False}
            ladder, conf = "OBSERVED", "low"
        else:
            diff = compare(base, alt)
            if diff["kind"] == "SAME_REPRESENTATION":
                outcome = "NO_DIFFERENTIAL"
                ladder, conf = "OBSERVED", "low"
            elif diff["kind"] == "MEANINGFUL_DIFFERENTIAL":
                outcome = "MEANINGFUL_DIFFERENTIAL"
                ladder, conf = "CANDIDATE", "medium"
            elif diff["kind"] == "VALIDATION_ERROR":
                outcome = "VALIDATION_ERROR"
                ladder, conf = "OBSERVED", "low"
            else:
                outcome = "OBSERVED_DIFFERENTIAL"
                ladder, conf = "OBSERVED", "low"

        stats["kinds"][outcome] = stats["kinds"].get(outcome, 0) + 1
        results.append({
            "schema": "bugbountyci.representation_diff.v1",
            "url": url[:300],
            "reason_selected": cand.get("reason_selected"),
            "baseline": {
                "accept": "text/html",
                "status": base.get("status"),
                "content_type": base.get("content_type"),
                "fingerprint": base.get("fingerprint"),
                "json_keys": base.get("json_keys") or [],
                "error": base.get("error"),
            },
            "alternate": {
                "accept": "application/json",
                "status": alt.get("status"),
                "content_type": alt.get("content_type"),
                "fingerprint": alt.get("fingerprint"),
                "json_keys": alt.get("json_keys") or [],
                "error": alt.get("error"),
            },
            "differential": diff,
            "outcome": outcome,
            "evidence_ladder": ladder,
            "confidence": conf,
            "next_pivot": "manual_review_fields" if outcome == "MEANINGFUL_DIFFERENTIAL" else "none",
            "limitations": (
                "Representation difference is evidence only — not a vulnerability. "
                "HTML vs JSON alone is not security impact."
            ),
            "provenance": "representation_differential+existing_surface",
        })

    out_path = os.path.join(out_dir, "representation_diffs.jsonl")
    with open(out_path, "w") as f:
        for row in results:
            f.write(json.dumps(row) + "\n")

    diagnosis = "NO_CANDIDATES"
    if stats["candidates"] > 0:
        diagnosis = "CANDIDATES_SELECTED"
    summary = {
        "schema": "bugbountyci.representation_summary.v1",
        "candidates": stats["candidates"],
        "pairs_run": stats["pairs_run"],
        "not_run": stats["not_run"],
        "kinds": stats["kinds"],
        "budget": args.budget,
        "diagnosis": diagnosis,
        "note": "candidate ≠ vulnerability; Accept differential is observational; NO_CANDIDATES ≠ clean target",
    }
    with open(os.path.join(out_dir, "representation_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    print(f"✅ representation differential: candidates={stats['candidates']} pairs={stats['pairs_run']} kinds={stats['kinds']}")


if __name__ == "__main__":
    main()
