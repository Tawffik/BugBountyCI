#!/usr/bin/env python3
"""
Build a clean HTTP hostname target list for expensive application probes.

Root cause addressed (Info-disclosure #142/#143, Arjun #141):
  live.txt / expensive_targets mix hostnames + pure IPs + http/https duplicates.
  Nested host×path×Tor loops then burn the full GHA step timeout.

Also ranks hostnames so test/api/admin surfaces are probed before static/cdn
mirrors (hunter-priority within the same bounded limit).

This script emits unique https://hostname lines (no pure IPs).
"""
from __future__ import annotations

import argparse
import re
import sys
from urllib.parse import urlparse

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Substring signals on the left-most label / full host (hunter priority).
_HIGH = (
    "test", "staging", "stage", "dev", "uat", "qa", "beta", "sandbox",
    "api", "admin", "internal", "intranet", "portal", "auth", "login",
    "sso", "oauth", "dashboard", "manage", "cms", "graphql", "swagger",
    "open-api", "openapi", "backend", "partner", "affiliates",
)
_LOW = (
    "static", "cdn", "img", "image", "images", "asset", "assets", "media",
    "font", "fonts", "video", "videos", "css", "js-cdn", "origin-www",
)


def _label_has_token(label: str, tok: str) -> bool:
    """Match token as whole label or hyphen/underscore segment — not substring.
    Avoids 'api' matching inside 'capital'."""
    if not label or not tok:
        return False
    if label == tok:
        return True
    parts = label.replace("_", "-").split("-")
    return tok in parts


def _host_score(host: str) -> int:
    h = (host or "").lower().rstrip(".")
    if not h:
        return -100
    score = 0
    labels = h.split(".")
    left = labels[0] if labels else ""
    for tok in _HIGH:
        if (
            _label_has_token(left, tok)
            or h.startswith(tok + ".")
            or any(_label_has_token(lab, tok) for lab in labels[:-1])
        ):
            score += 10
            break
    for tok in _LOW:
        if _label_has_token(left, tok) or h.startswith(tok + ".") or any(
            _label_has_token(lab, tok) for lab in labels[:-1]
        ):
            score -= 8
            break
    if left in ("www", "m", "mobile"):
        score -= 2
    return score


def iter_host_entries(lines):
    """Yield (host, first_index) in encounter order, skipping IPs/dupes."""
    seen = {}
    for idx, line in enumerate(lines):
        u = (line or "").strip()
        if not u or u.startswith("#"):
            continue
        # ranked files: "105 https://host" — take last token always when spaced
        if " " in u:
            parts = u.split()
            u = parts[-1] if parts else u
        if "://" not in u:
            u = "https://" + u
        try:
            host = (urlparse(u).hostname or "").lower()
        except Exception:
            continue
        if not host or IP_RE.fullmatch(host):
            continue
        if host not in seen:
            seen[host] = idx
    for host, idx in seen.items():
        yield host, idx


def filter_lines(lines, limit: int) -> list[str]:
    entries = list(iter_host_entries(lines))
    # Rank: higher score first; stable by first-seen index
    entries.sort(key=lambda hi: (-_host_score(hi[0]), hi[1]))
    out = []
    for host, _ in entries:
        out.append(f"https://{host}")
        if limit and len(out) >= limit:
            break
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("inputs", nargs="+", help="input files (merged in order)")
    ap.add_argument("-o", "--output", required=True, help="output path")
    ap.add_argument("--limit", type=int, default=25, help="max hostnames (0=unlimited)")
    args = ap.parse_args(argv)

    lines = []
    for path in args.inputs:
        try:
            with open(path, errors="ignore") as f:
                lines.extend(f.readlines())
        except OSError:
            continue
    out = filter_lines(lines, args.limit)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + ("\n" if out else ""))
    print(f"hostname_targets={len(out)} limit={args.limit} -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
