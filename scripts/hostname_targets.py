#!/usr/bin/env python3
"""
Build a clean HTTP hostname target list for expensive application probes.

Root cause addressed (Info-disclosure #142/#143, Arjun #141):
  live.txt / expensive_targets mix hostnames + pure IPs + http/https duplicates.
  Nested host×path×Tor loops then burn the full GHA step timeout.

This script emits unique https://hostname lines (no pure IPs), stable order.
"""
from __future__ import annotations

import argparse
import re
import sys
from urllib.parse import urlparse

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def iter_hosts(lines):
    seen = set()
    for line in lines:
        u = (line or "").strip()
        if not u or u.startswith("#"):
            continue
        if "://" not in u:
            u = "https://" + u
        try:
            host = (urlparse(u).hostname or "").lower()
        except Exception:
            continue
        if not host or IP_RE.fullmatch(host):
            continue
        if host in seen:
            continue
        seen.add(host)
        yield f"https://{host}"


def filter_lines(lines, limit: int) -> list[str]:
    out = []
    for h in iter_hosts(lines):
        out.append(h)
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
