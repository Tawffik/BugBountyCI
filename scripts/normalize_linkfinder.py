#!/usr/bin/env python3
"""
normalize_linkfinder.py — classify LinkFinder raw lines without deleting evidence.

Input lines (workflow format):
  [source.js] <path-or-url>

Output:
  <RD>/js_deep/linkfinder_normalized.jsonl
  <RD>/js_deep/linkfinder_summary.json

Classifications:
  API_ROUTE | WEB_ROUTE | STATIC_ASSET | EXTERNAL | INVALID | UNKNOWN

Does NOT claim vulnerabilities. Preserves raw_value + source_js.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from urllib.parse import urlparse, urljoin

LINE_RE = re.compile(r"^\[([^\]]+)\]\s+(.+)$")
API_RE = re.compile(
    r"(?:/api(?:/|$|\?|-catalog)|/graphql(?:/|$|\?)|/rest(?:/|$|\?)"
    r"|/v\d+/(?:[A-Za-z_])|/(?:openapi|swagger)(?:\.json|/|$|\?))",
    re.I,
)
STATIC_EXT = re.compile(
    r"\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|avif|mp4|webm)(?:\?|$)",
    re.I,
)
STATIC_PREFIX = re.compile(r"^(?:\./|\.\./|assets/|static/|chunks?/|dist/)", re.I)


def in_scope_host(host: str, allowed: set[str]) -> bool:
    if not host:
        return False
    h = host.lower().rstrip(".")
    if h in allowed:
        return True
    for a in allowed:
        if h.endswith("." + a):
            return True
    return False


def build_allowed(target: str, results_dir: str) -> set[str]:
    allowed: set[str] = set()
    t = (target or "").strip().lower()
    if t:
        allowed.add(t)
        if not t.startswith("www."):
            allowed.add("www." + t)
        allowed.add("api." + t)
        allowed.add("app." + t)
    for rel in ("live/live.txt", "live/verified.txt", "live/scan_order.txt"):
        path = os.path.join(results_dir, rel)
        if not os.path.isfile(path):
            continue
        with open(path, "r", errors="ignore") as f:
            for line in f:
                u = line.strip().split()[0] if line.strip() else ""
                if not u.startswith("http"):
                    continue
                try:
                    h = urlparse(u).hostname
                except Exception:
                    h = None
                if h:
                    allowed.add(h.lower())
    return allowed


def classify_path(path: str, allowed: set[str]) -> tuple[str, str | None, str]:
    """Return (classification, resolved_url_or_none, note)."""
    raw = (path or "").strip()
    if not raw or len(raw) > 2000:
        return "INVALID", None, "empty_or_too_long"

    # Absolute URL
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            p = urlparse(raw)
        except Exception:
            return "INVALID", None, "bad_url"
        host = (p.hostname or "").lower()
        if not host:
            return "INVALID", None, "no_host"
        if not in_scope_host(host, allowed):
            return "EXTERNAL", raw, "out_of_scope_host"
        if STATIC_EXT.search(p.path or ""):
            return "STATIC_ASSET", raw, "static_extension"
        if API_RE.search(p.path or ""):
            return "API_ROUTE", raw, "api_pattern"
        if (p.path or "/") in ("/", ""):
            return "WEB_ROUTE", raw, "root"
        return "WEB_ROUTE", raw, "in_scope_url"

    # Relative / path-like
    if STATIC_EXT.search(raw) or STATIC_PREFIX.match(raw):
        return "STATIC_ASSET", None, "relative_or_asset_bundle"

    if raw.startswith("/") and API_RE.search(raw):
        return "API_ROUTE", None, "api_path_unbound"

    if raw.startswith("/") and not STATIC_EXT.search(raw):
        return "WEB_ROUTE", None, "absolute_path_unbound"

    # Bare module names without extension often still chunks
    if re.match(r"^[A-Za-z0-9_./-]+$", raw) and ("chunk" in raw.lower() or "dist-" in raw.lower()):
        return "STATIC_ASSET", None, "chunk_like"

    return "UNKNOWN", None, "unclassified"


def parse_line(line: str) -> tuple[str | None, str | None]:
    s = line.strip()
    if not s:
        return None, None
    m = LINE_RE.match(s)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    # bare path/url without source prefix
    return None, s


def normalize_file(
    input_path: str,
    results_dir: str,
    target: str,
) -> dict:
    allowed = build_allowed(target, results_dir)
    out_dir = os.path.join(results_dir, "js_deep")
    os.makedirs(out_dir, exist_ok=True)
    out_jsonl = os.path.join(out_dir, "linkfinder_normalized.jsonl")
    counts: Counter = Counter()
    rows = 0

    with open(out_jsonl, "w", encoding="utf-8") as out:
        if os.path.isfile(input_path):
            with open(input_path, "r", errors="ignore") as f:
                for line in f:
                    source_js, raw = parse_line(line)
                    if raw is None:
                        continue
                    cls, resolved, note = classify_path(raw, allowed)
                    counts[cls] += 1
                    rows += 1
                    rec = {
                        "schema": "bugbountyci.linkfinder_normalized.v1",
                        "raw_value": raw,
                        "source_js": source_js,
                        "classification": cls,
                        "resolved_url": resolved,
                        "scope_result": (
                            "in_scope"
                            if cls in ("API_ROUTE", "WEB_ROUTE", "STATIC_ASSET") and resolved
                            else "n/a"
                            if resolved is None
                            else "external"
                            if cls == "EXTERNAL"
                            else "unknown"
                        ),
                        "note": note,
                        "confidence": (
                            "high"
                            if cls in ("STATIC_ASSET", "EXTERNAL", "API_ROUTE")
                            else "medium"
                            if cls == "WEB_ROUTE"
                            else "low"
                        ),
                    }
                    out.write(json.dumps(rec, ensure_ascii=False) + "\n")

    summary = {
        "schema": "bugbountyci.linkfinder_summary.v1",
        "raw_lines": rows,
        "counts": dict(counts),
        "api_routes": counts.get("API_ROUTE", 0),
        "web_routes": counts.get("WEB_ROUTE", 0),
        "static_assets": counts.get("STATIC_ASSET", 0),
        "external": counts.get("EXTERNAL", 0),
        "invalid": counts.get("INVALID", 0),
        "unknown": counts.get("UNKNOWN", 0),
        "note": (
            "raw_lines is NOT api_endpoint_count. "
            "STATIC_ASSET (./chunk.js, assets/*.js) must not be treated as API surface. "
            "Raw file linkfinder_endpoints.txt is preserved."
        ),
    }
    with open(os.path.join(out_dir, "linkfinder_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default="")
    ap.add_argument(
        "--input",
        default="",
        help="default: <results-dir>/js_deep/linkfinder_endpoints.txt",
    )
    args = ap.parse_args(argv)
    rd = args.results_dir
    inp = args.input or os.path.join(rd, "js_deep", "linkfinder_endpoints.txt")
    summary = normalize_file(inp, rd, args.target)
    print(
        f"✅ linkfinder normalize: raw={summary['raw_lines']} "
        f"api={summary['api_routes']} web={summary['web_routes']} "
        f"static={summary['static_assets']} external={summary['external']} "
        f"unknown={summary['unknown']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
