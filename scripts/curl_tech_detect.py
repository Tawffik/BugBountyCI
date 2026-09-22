#!/usr/bin/env python3
"""Enrich live/tech.json records that only have host_curl_fallback.

When httpx is rejected (Cloudflare JA3), curl still gets status/headers/body.
This script fingerprints common stacks from headers + a short body sample —
enough for Wolf selector / target_profile, not a full Wappalyzer replacement.

Usage:
  python3 scripts/curl_tech_detect.py --results-dir results/TS [--timeout 8]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# (name, header_regex OR body_regex)
HEADER_RULES = [
    ("Cloudflare", re.compile(r"(?i)cloudflare|cf-ray|__cf"), "header"),
    ("nginx", re.compile(r"(?i)\bnginx\b"), "server"),
    ("Apache", re.compile(r"(?i)\bapache\b"), "server"),
    ("IIS", re.compile(r"(?i)microsoft-iis|IIS/"), "server"),
    ("Cloudfront", re.compile(r"(?i)cloudfront|x-amz-cf"), "header"),
    ("Akamai", re.compile(r"(?i)akamai|x-akamai"), "header"),
    ("Vercel", re.compile(r"(?i)\bvercel\b|x-vercel"), "header"),
    ("Netlify", re.compile(r"(?i)\bnetlify\b"), "header"),
    ("Fastly", re.compile(r"(?i)\bfastly\b"), "header"),
    ("Sucuri", re.compile(r"(?i)\bsucuri\b"), "header"),
    ("Incapsula", re.compile(r"(?i)incapsula|imperva"), "header"),
]

BODY_RULES = [
    ("WordPress", re.compile(r"(?i)wp-content|wp-includes|wordpress")),
    ("Next.js", re.compile(r"(?i)__NEXT_DATA__|_next/static")),
    ("Nuxt", re.compile(r"(?i)__NUXT__|_nuxt/")),
    ("React", re.compile(r"(?i)data-reactroot|react-dom")),
    ("Angular", re.compile(r"(?i)ng-version|angular\.js")),
    ("Vue.js", re.compile(r"(?i)data-v-[a-f0-9]{8}|vue\.runtime")),
    ("Laravel", re.compile(r"(?i)laravel_session|XSRF-TOKEN")),
    ("Django", re.compile(r"(?i)csrfmiddlewaretoken|django")),
    ("Shopify", re.compile(r"(?i)cdn\.shopify|Shopify\.theme")),
    ("Drupal", re.compile(r"(?i)Drupal\.settings|drupal\.js")),
    ("jQuery", re.compile(r"(?i)jquery[-.]?\d|jquery\.min\.js")),
    ("Bootstrap", re.compile(r"(?i)bootstrap\.(min\.)?(css|js)")),
]


def curl_probe(url: str, timeout: int, ua: str) -> tuple[int, str, str]:
    """Return (status, headers_text, body_sample)."""
    cmd = [
        "curl", "-skL", "--max-time", str(timeout),
        "-D", "-", "-o", "-",
        "-H", f"User-Agent: {ua}",
        "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "--max-redirs", "3",
        url,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
        raw = (p.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        return 0, "", ""
    # Split headers / body on first blank line after status
    parts = raw.split("\r\n\r\n", 1)
    if len(parts) == 1:
        parts = raw.split("\n\n", 1)
    headers = parts[0] if parts else ""
    body = parts[1][:8000] if len(parts) > 1 else ""
    status = 0
    m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", headers)
    if m:
        status = int(m.group(1))
    return status, headers, body


def detect(headers: str, body: str) -> list[str]:
    found: list[str] = []
    server = ""
    for line in headers.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[-1].strip()
            break
    blob = headers
    for name, rx, kind in HEADER_RULES:
        target = server if kind == "server" else blob
        if rx.search(target) and name not in found:
            found.append(name)
    for name, rx in BODY_RULES:
        if rx.search(body) and name not in found:
            found.append(name)
    return found


def load_ndjson(path: Path) -> list[dict]:
    rows = []
    if not path.is_file() or path.stat().st_size == 0:
        return rows
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument(
        "--ua",
        default=os.environ.get(
            "SCAN_USER_AGENT",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        ),
    )
    args = ap.parse_args()
    rd = Path(args.results_dir)
    tech_path = rd / "live" / "tech.json"
    rows = load_ndjson(tech_path)
    if not rows:
        # also try live.json
        rows = load_ndjson(rd / "live" / "live.json")
    if not rows:
        print("ℹ️ curl_tech_detect: no tech/live records to enrich")
        return 0

    enriched = 0
    out_lines = []
    for rec in rows:
        url = rec.get("url") or rec.get("input") or ""
        if not url:
            out_lines.append(json.dumps(rec, ensure_ascii=False))
            continue
        # Only enrich when technologies missing
        existing = rec.get("tech") or rec.get("technologies") or []
        if isinstance(existing, str):
            existing = [existing] if existing else []
        if existing and not rec.get("host_curl_fallback"):
            out_lines.append(json.dumps(rec, ensure_ascii=False))
            continue
        status, headers, body = curl_probe(url, args.timeout, args.ua)
        techs = detect(headers, body)
        if status and not rec.get("status_code"):
            rec["status_code"] = status
        if techs:
            rec["technologies"] = techs
            rec["tech_source"] = "curl_tech_detect"
            enriched += 1
        out_lines.append(json.dumps(rec, ensure_ascii=False))

    tech_path.parent.mkdir(parents=True, exist_ok=True)
    tech_path.write_text("\n".join(out_lines) + ("\n" if out_lines else ""))
    print(f"✅ curl_tech_detect: enriched {enriched}/{len(rows)} records → {tech_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
