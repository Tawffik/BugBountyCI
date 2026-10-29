#!/usr/bin/env python3
"""
cloud_exposure_engine.py — Cloud Exposure Intelligence V1 for Zero Track.

Aligns with Notion: Cloud Exposure Intelligence — End-to-End Workflow & Verification Gates.

V1 scope (bounded, read-only):
  Gate 1: Discover provider hints from existing recon artifacts (URLs, JS, DNS-ish files).
  Gate 2: Normalize + scope (pipeline.scope); quarantine OOS.
  Gate 3: Optional bounded HEAD/GET on in-scope candidate bucket roots only (no brute, no write).
  Gate 4–5: Classify conservatively — clue / lead / content_supported; never CONFIRMED.
  Gate 6: Write JSONL + phase health; Hunter consumes as LEAD.

Guardrails:
  - No PUT/POST/DELETE, no signature tampering, no object-key guessing beyond known URLs.
  - 403 ≠ vulnerability; 200 listing evidence elevates to content_supported only with body markers.
  - Third-party / ambiguous → quarantined.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

# --- patterns ---
S3_HOST = re.compile(
    r"(?:^|\.)s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com$|"
    r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com$",
    re.I,
)
S3_PATH_STYLE = re.compile(r"(?i)s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com")
GCS_HOST = re.compile(r"(?:^|\.)storage\.googleapis\.com$|(?:^|\.)storage\.cloud\.google\.com$", re.I)
AZURE_BLOB = re.compile(r"\.blob\.core\.windows\.net$", re.I)
CLOUDFRONT = re.compile(r"\.cloudfront\.net$", re.I)
R2_HOST = re.compile(r"\.r2\.cloudflarestorage\.com$", re.I)

# URL / string extraction
URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
S3_URL_RE = re.compile(
    r"https?://[a-z0-9][a-z0-9.\-]{1,80}\.s3[.\-][a-z0-9.\-]*amazonaws\.com/[^\s\"'<>\\)]*",
    re.I,
)
GCS_URL_RE = re.compile(
    r"https?://storage\.googleapis\.com/[a-z0-9.\-_]{1,80}/[^\s\"'<>\\)]*",
    re.I,
)
SIGNED_HINT = re.compile(r"(?i)[?&](X-Amz-Signature|X-Amz-Credential|Signature|sig)=")

LISTING_MARKERS = (
    "<ListBucketResult",
    "<ListBlobResult",
    "<Contents>",
    "<Key>",
    "<?xml",
)
DENY_MARKERS = (
    "<Code>AccessDenied</Code>",
    "<Code>AllAccessDisabled</Code>",
    "<Error><Code>AccessDenied",
    "AccessDenied",
    "AuthorizationHeaderMalformed",
)
NOSUCH_MARKERS = (
    "<Code>NoSuchBucket</Code>",
    "<Code>NoSuchKey</Code>",
    "NoSuchBucket",
)

DETECTOR_ID = "cloud_exposure_v1"
DETECTOR_VERSION = "1.0.0"

# Cap active probes hard
MAX_ACTIVE_PROBES = 12
MAX_CANDIDATES_OUT = 80
BODY_SNIPPET = 400


def _scope_funcs():
    try:
        from pipeline.scope import in_scope_host, in_scope_url, resolve_target_domain
        return in_scope_host, in_scope_url, resolve_target_domain
    except Exception:
        try:
            sys.path.insert(0, os.getcwd())
            from pipeline.scope import in_scope_host, in_scope_url, resolve_target_domain
            return in_scope_host, in_scope_url, resolve_target_domain
        except Exception:
            return None, None, None


def classify_provider(host: str, path: str = "") -> Tuple[str, float]:
    h = (host or "").lower().strip(".")
    if not h:
        return "unknown", 0.0
    if CLOUDFRONT.search(h) or h.endswith("cloudfront.net"):
        return "cloudfront", 0.9
    if S3_HOST.search(h) or "s3.amazonaws.com" in h or "s3-" in h and "amazonaws.com" in h:
        return "s3", 0.95
    if GCS_HOST.search(h):
        return "gcs", 0.95
    if AZURE_BLOB.search(h):
        return "azure_blob", 0.9
    if R2_HOST.search(h):
        return "r2", 0.85
    if path.startswith("/s3") or "amazonaws" in h:
        return "s3_ambiguous", 0.4
    return "unknown", 0.0


def normalize_asset(url: str) -> Dict[str, str]:
    try:
        p = urlparse(url.strip())
        host = (p.hostname or "").lower()
        path = p.path or "/"
        scheme = p.scheme or "https"
        # strip query for storage root identity; keep signed flag separately
        root = f"{scheme}://{host}{path.split('?')[0]}"
        return {"url": url.strip(), "host": host, "path": path, "root": root, "scheme": scheme}
    except Exception:
        return {"url": url, "host": "", "path": "", "root": url, "scheme": "https"}


def _read_lines(path: str, limit: int = 5000) -> List[str]:
    if not path or not os.path.isfile(path):
        return []
    out: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= limit:
                    break
                s = line.strip()
                if s:
                    out.append(s)
    except OSError:
        pass
    return out


def harvest_urls(results_dir: str) -> List[Tuple[str, str]]:
    """Return list of (url, source_artifact_ref)."""
    pairs: List[Tuple[str, str]] = []
    files = [
        ("urls/all.txt", 8000),
        ("js/endpoints.txt", 2000),
        ("js/urls.txt", 2000),
        ("source_maps/endpoints.txt", 500),
        ("live/cloud_buckets.txt", 200),
        ("js_deep/linkfinder_normalized.jsonl", 2000),
    ]
    for rel, lim in files:
        path = os.path.join(results_dir, rel)
        if not os.path.isfile(path):
            continue
        if rel.endswith(".jsonl"):
            for line in _read_lines(path, lim):
                try:
                    row = json.loads(line)
                    u = row.get("url") or row.get("endpoint") or row.get("link") or ""
                    if u.startswith("http"):
                        pairs.append((u, rel))
                except json.JSONDecodeError:
                    for m in URL_RE.findall(line):
                        pairs.append((m.rstrip(".,;"), rel))
        else:
            for line in _read_lines(path, lim):
                # cloud_buckets format: "S3: https://..."
                if line.upper().startswith("S3:") or line.upper().startswith("GCS:"):
                    m = URL_RE.search(line)
                    if m:
                        pairs.append((m.group(0), rel))
                    continue
                for m in URL_RE.findall(line):
                    pairs.append((m.rstrip(".,;"), rel))
                for m in S3_URL_RE.findall(line):
                    pairs.append((m.rstrip(".,;"), rel))
                for m in GCS_URL_RE.findall(line):
                    pairs.append((m.rstrip(".,;"), rel))
    return pairs


def name_guess_candidates(target: str) -> List[Tuple[str, str]]:
    """Legacy-compatible name guesses — tagged as low confidence clue source."""
    base = re.sub(r"\.(com|net|org|io|co|dev|app)(\.[a-z]{2})?$", "", target, flags=re.I)
    base = base.split(".")[-1] if base else target
    if not base or len(base) < 2:
        return []
    out = []
    for suffix in ("", "-backup", "-assets", "-media", "-dev", "-staging", "-files", "-data", "-public", "-static"):
        b = f"{base}{suffix}"
        out.append((f"https://{b}.s3.amazonaws.com/", "name_guess"))
        out.append((f"https://storage.googleapis.com/{b}/", "name_guess"))
    return out


def scope_disposition(url: str, target: str, in_scope_url, in_scope_host, resolve_target_domain) -> str:
    if not target:
        return "ambiguous"
    try:
        if in_scope_url and in_scope_url(url, target):
            return "in_scope"
        host = urlparse(url).hostname or ""
        # Bucket name often embeds target brand — allow if host contains target base
        td = resolve_target_domain(target) if resolve_target_domain else target
        base = td.split(".")[0] if td else ""
        if base and len(base) >= 3 and base.lower() in (host or "").lower():
            return "name_affiliated"  # not automatic in-scope for active probe of third-party
        if in_scope_host and host and in_scope_host(host, target):
            return "in_scope"
    except Exception:
        return "ambiguous"
    # Pure amazonaws/gcs hosts without target brand → third_party unless name_guess for this run
    return "third_party_or_oos"


def classify_body(status: int, body: str, headers: str) -> Tuple[str, str]:
    """Return (response_class, reason)."""
    b = body or ""
    bl = b.lower()
    if status == 0:
        return "error", "network_or_timeout"
    if status == 429:
        return "rate_limited", "http_429"
    if status >= 500:
        return "provider_error", f"http_{status}"
    if status in (401,):
        return "auth_required", "http_401"
    if status == 403:
        if any(m.lower() in bl for m in DENY_MARKERS) or "accessdenied" in bl:
            return "access_denied", "provider_access_denied"
        return "access_denied", "http_403"
    if status == 404:
        if any(m.lower() in bl for m in NOSUCH_MARKERS):
            return "not_found", "no_such_bucket_or_key"
        return "not_found", "http_404"
    if status in (301, 302, 303, 307, 308):
        return "redirect", f"http_{status}"
    if status == 200:
        if any(m in b for m in LISTING_MARKERS) and ("<Key>" in b or "<Contents>" in b or "ListBucket" in b):
            return "listing_evidence", "xml_list_markers"
        if len(b) < 50 and "html" not in bl:
            return "empty_or_minimal_200", "short_body"
        if "<html" in bl or "<!doctype" in bl:
            return "html_200", "html_body"
        return "content_200", "http_200_body"
    return "other", f"http_{status}"


def disposition_from_class(resp_class: str, source: str) -> str:
    """final_disposition: provider_clue | exposure_lead | content_supported | observed."""
    if resp_class == "listing_evidence":
        return "content_supported"
    if resp_class in ("content_200", "access_denied") and source != "name_guess":
        # access_denied on known URL = existence lead, not vuln
        return "exposure_lead" if resp_class == "content_200" else "provider_clue"
    if resp_class == "access_denied":
        return "provider_clue"  # bucket may exist
    if resp_class in ("not_found", "error", "rate_limited"):
        return "observed"
    if source == "name_guess":
        return "provider_clue"
    return "provider_clue"


def active_probe(url: str, timeout: float = 8.0) -> Dict[str, Any]:
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "BugBountyCI-CloudExposure/1.0 (authorized-recon; read-only)"},
    )
    status = 0
    body = ""
    hdrs = ""
    err = ""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200) or 200
            hdrs = str(dict(resp.headers))[:500]
            raw = resp.read(8000)
            body = raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            body = e.read(8000).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        hdrs = str(dict(e.headers or {}))[:500]
        err = f"HTTPError:{e.code}"
    except Exception as e:
        err = type(e).__name__
        status = 0
    resp_class, reason = classify_body(status, body, hdrs)
    # redact signed query from stored URL evidence
    safe_url = url
    if SIGNED_HINT.search(url):
        safe_url = url.split("?")[0] + "?[REDACTED_SIGNED_QUERY]"
    snippet = body[:BODY_SNIPPET]
    for secretish in re.findall(r"(?i)(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})", snippet):
        snippet = snippet.replace(secretish, "[REDACTED_KEY]")
    return {
        "status": status,
        "response_class": resp_class,
        "reason": reason,
        "error": err,
        "body_snippet_redacted": snippet,
        "safe_url": safe_url,
    }


def run(
    results_dir: str,
    target: str,
    enable_active: bool = True,
    max_probes: int = MAX_ACTIVE_PROBES,
) -> Dict[str, Any]:
    in_scope_host, in_scope_url, resolve_target_domain = _scope_funcs()
    harvested = harvest_urls(results_dir)
    harvested.extend(name_guess_candidates(target))

    candidates: Dict[str, Dict[str, Any]] = {}
    quarantined: List[Dict[str, Any]] = []

    for url, source in harvested:
        asset = normalize_asset(url)
        host = asset["host"]
        if not host:
            continue
        provider, conf = classify_provider(host, asset["path"])
        if provider == "unknown" and source != "name_guess":
            # keep only if strong S3/GCS pattern in full URL
            if not (S3_URL_RE.search(url) or GCS_URL_RE.search(url) or "cloudfront.net" in host):
                continue
            provider, conf = "unknown_cloudish", 0.3

        signed = bool(SIGNED_HINT.search(url))
        scope = scope_disposition(url, target, in_scope_url, in_scope_host, resolve_target_domain)
        if source == "name_guess":
            scope = "name_guess"
            conf = min(conf, 0.35)

        key = asset["root"].lower()
        if scope in ("third_party_or_oos", "ambiguous") and source != "name_guess" and provider not in (
            "s3",
            "gcs",
            "azure_blob",
            "cloudfront",
            "r2",
        ):
            quarantined.append({"url": url, "reason": scope, "source": source})
            continue

        rec = candidates.get(key) or {
            "asset_normalized": asset["root"],
            "host": host,
            "provider_hypothesis": provider,
            "confidence": conf,
            "sources": [],
            "scope_disposition": scope,
            "signed_url_observed": False,
            "urls_examples": [],
        }
        if source not in rec["sources"]:
            rec["sources"].append(source)
        rec["confidence"] = max(rec["confidence"], conf)
        rec["signed_url_observed"] = rec["signed_url_observed"] or signed
        if len(rec["urls_examples"]) < 3:
            example = url.split("?")[0] + ("?[REDACTED]" if signed else "")
            if example not in rec["urls_examples"]:
                rec["urls_examples"].append(example)
        # Prefer better scope label
        if scope == "in_scope":
            rec["scope_disposition"] = "in_scope"
        candidates[key] = rec

    findings: List[Dict[str, Any]] = []
    probes_done = 0
    # Probe priority: in-scope cloud hosts first, then name_guess limited
    ordered = sorted(
        candidates.values(),
        key=lambda r: (
            0 if r["scope_disposition"] == "in_scope" else 1 if r["scope_disposition"] == "name_guess" else 2,
            -r["confidence"],
        ),
    )

    for rec in ordered[:MAX_CANDIDATES_OUT]:
        probe_result = None
        final = "provider_clue"
        execution = "passive_only"

        allow_active = (
            enable_active
            and probes_done < max_probes
            and rec["provider_hypothesis"] in ("s3", "gcs", "azure_blob", "r2", "s3_ambiguous")
            and rec["scope_disposition"] in ("in_scope", "name_guess", "name_affiliated")
        )
        if allow_active:
            # probe root only
            probe_url = rec["asset_normalized"]
            if not probe_url.endswith("/"):
                # object URL — still GET the same URL once (known from artifacts)
                probe_url = rec["urls_examples"][0] if rec["urls_examples"] else probe_url
            probe_result = active_probe(probe_url)
            probes_done += 1
            execution = "read_only_get"
            final = disposition_from_class(probe_result["response_class"], rec["sources"][0] if rec["sources"] else "")
            if probe_result["response_class"] == "listing_evidence":
                final = "content_supported"

        dedupe = hashlib.sha256(
            f"{rec['asset_normalized']}|{rec['provider_hypothesis']}".encode()
        ).hexdigest()[:16]

        finding = {
            "schema": "bugbountyci.cloud_exposure.v1",
            "detector_id": DETECTOR_ID,
            "detector_version": DETECTOR_VERSION,
            "target": target,
            "asset_normalized": rec["asset_normalized"],
            "host": rec["host"],
            "provider_hypothesis": rec["provider_hypothesis"],
            "confidence": round(rec["confidence"], 3),
            "scope_disposition": rec["scope_disposition"],
            "source_artifact_refs": rec["sources"],
            "signed_url_observed": rec["signed_url_observed"],
            "url_examples_redacted": rec["urls_examples"],
            "execution_status": execution,
            "final_disposition": final,  # never confirmed
            "classification": "LEAD" if final in ("exposure_lead", "content_supported") else "OBSERVED",
            "never_auto_confirmed": True,
            "dedupe_key": dedupe,
            "probe": probe_result,
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        findings.append(finding)

    out_dir = os.path.join(results_dir, "detection")
    os.makedirs(out_dir, exist_ok=True)
    findings_path = os.path.join(out_dir, "cloud_exposure_findings.jsonl")
    with open(findings_path, "w", encoding="utf-8") as f:
        for row in findings:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    # Human-readable leads for triage compatibility
    txt_path = os.path.join(results_dir, "live", "cloud_buckets.txt")
    os.makedirs(os.path.dirname(txt_path), exist_ok=True)
    with open(txt_path, "w", encoding="utf-8") as f:
        for row in findings:
            if row["final_disposition"] in ("content_supported", "exposure_lead", "provider_clue"):
                st = (row.get("probe") or {}).get("status", "-")
                rc = (row.get("probe") or {}).get("response_class", "passive")
                f.write(
                    f"{row['provider_hypothesis'].upper()}: {row['asset_normalized']} "
                    f"[disp={row['final_disposition']} status={st} class={rc}]\n"
                )

    summary = {
        "schema": "bugbountyci.cloud_exposure_summary.v1",
        "detector_id": DETECTOR_ID,
        "detector_version": DETECTOR_VERSION,
        "target": target,
        "candidates": len(candidates),
        "findings": len(findings),  # historical key; treat as observation rows
        "clues": len(findings),
        "operator_label": "clues_not_vulnerabilities",
        "probes": probes_done,
        "quarantined": len(quarantined),
        "by_disposition": {},
        "by_provider": {},
        "auto_confirmed": 0,
        "note": "403/AccessDenied is existence clue only — not a vulnerability. CONFIRMED never emitted.",
    }
    for row in findings:
        summary["by_disposition"][row["final_disposition"]] = summary["by_disposition"].get(row["final_disposition"], 0) + 1
        summary["by_provider"][row["provider_hypothesis"]] = summary["by_provider"].get(row["provider_hypothesis"], 0) + 1

    with open(os.path.join(out_dir, "cloud_exposure_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")

    # phase health
    phase_dir = os.path.join(results_dir, "meta", "phases")
    os.makedirs(phase_dir, exist_ok=True)
    status = "ok" if findings or probes_done >= 0 else "empty"
    if not findings and not candidates:
        status = "empty"
    phase = {
        "schema": "bugbountyci.phase.v1",
        "phase": "cloud_exposure",
        "status": status,
        "counts": {
            "candidates": len(candidates),
            "findings": len(findings),
            "probes": probes_done,
            "quarantined": len(quarantined),
        },
        "note": summary["note"],
    }
    with open(os.path.join(phase_dir, "cloud_exposure.json"), "w", encoding="utf-8") as f:
        json.dump(phase, f, indent=2)
        f.write("\n")

    with open(os.path.join(out_dir, "cloud_exposure_quarantine.jsonl"), "w", encoding="utf-8") as f:
        for q in quarantined[:200]:
            f.write(json.dumps(q, ensure_ascii=False) + "\n")

    print(
        f"✅ cloud_exposure: candidates={len(candidates)} clues={len(findings)} (not vulns) "
        f"probes={probes_done} quarantined={len(quarantined)} dispositions={summary['by_disposition']}"
    )
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="Cloud Exposure Intelligence V1")
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--no-active", action="store_true", help="Passive classification only")
    ap.add_argument("--max-probes", type=int, default=MAX_ACTIVE_PROBES)
    args = ap.parse_args()
    run(
        args.results_dir,
        args.target,
        enable_active=not args.no_active,
        max_probes=max(0, min(args.max_probes, 30)),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
