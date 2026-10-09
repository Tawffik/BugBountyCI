#!/usr/bin/env python3
"""Select unique https://hostname/ targets for Arjun (skip pure IPs, dedupe)."""
from __future__ import annotations

import re
import sys
from urllib.parse import urlparse


def filter_arjun_targets(lines, limit: int = 15) -> list[str]:
    seen = set()
    out = []
    for line in lines:
        u = (line or "").strip()
        if not u or u.startswith("#"):
            continue
        if "://" not in u:
            u = "https://" + u
        try:
            p = urlparse(u)
        except Exception:
            continue
        host = (p.hostname or "").lower()
        if not host:
            continue
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            continue
        if host in seen:
            continue
        seen.add(host)
        out.append(f"https://{host}/")
        if len(out) >= limit:
            break
    return out


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    src = argv[0] if argv else "-"
    limit = int(argv[1]) if len(argv) > 1 else 15
    if src == "-":
        lines = sys.stdin.readlines()
    else:
        with open(src, errors="ignore") as f:
            lines = f.readlines()
    out = filter_arjun_targets(lines, limit=limit)
    sys.stdout.write("\n".join(out) + ("\n" if out else ""))
    print(f"arjun targets={len(out)} (hostname https only)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
