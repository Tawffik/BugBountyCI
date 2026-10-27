#!/usr/bin/env python3
"""Strip tool banners/noise from CloudFail/CloakQuest text artifacts (operator clarity)."""
from __future__ import annotations

import re
import sys
from pathlib import Path

BANNER_RE = re.compile(
    r"^(_{3,}|[-=]{5,}|\s*$|.*cloudfail.*|.*cloakquest.*|.*github\.com.*|"
    r".*created by.*|.*scanning for.*|.*checking if.*|.*do you have.*|"
    r".*uncover the true.*|.*twitter.*|.*discord.*)",
    re.I,
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USEFUL_RE = re.compile(r"(?i)(real ip|visible ip|cloudflare|not using|origin|\d+\.\d+\.\d+\.\d+)")


def clean_file(path: Path) -> int:
    if not path.is_file():
        return 0
    raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    kept = []
    for line in raw:
        s = line.strip()
        if not s:
            continue
        if BANNER_RE.match(s) and not IP_RE.search(s):
            continue
        # drop pure ASCII art lines
        if len(s) > 20 and sum(ch.isalnum() for ch in s) < len(s) * 0.3 and not IP_RE.search(s):
            continue
        if IP_RE.search(s) or USEFUL_RE.search(s):
            kept.append(s)
    # dedupe preserve order
    out = []
    seen = set()
    for k in kept:
        if k in seen:
            continue
        seen.add(k)
        out.append(k)
    path.write_text(("\n".join(out) + ("\n" if out else "")), encoding="utf-8")
    return len(out)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sanitize_cloud_origin_outputs.py <results_dir>", file=sys.stderr)
        return 2
    rd = Path(sys.argv[1])
    n = 0
    for rel in ("cloud/cloudfail.txt", "cloud/cloakquest.txt"):
        n += clean_file(rd / rel)
    print(f"✅ cloud origin sanitized useful_lines≈{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
