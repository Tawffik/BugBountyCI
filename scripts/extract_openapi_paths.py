#!/usr/bin/env python3
"""Append OpenAPI/Swagger path keys and segments to a wordlist-friendly file."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SKIP = {"api", "v1", "v2", "v3", "v4", "http", "https"}


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: extract_openapi_paths.py <body.json> <out.txt>", file=sys.stderr)
        return 2
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    try:
        data = json.loads(src.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return 0
    paths = data.get("paths") if isinstance(data, dict) else None
    if not isinstance(paths, dict):
        return 0
    lines: list[str] = []
    for p in list(paths.keys())[:500]:
        p = (p or "").strip()
        if not p.startswith("/"):
            continue
        lines.append(p)
        for seg in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", p):
            if seg.lower() not in SKIP:
                lines.append(seg)
    if not lines:
        return 0
    with dst.open("a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
