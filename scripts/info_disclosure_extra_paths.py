#!/usr/bin/env python3
"""Emit tech-aware info-disclosure paths from live/tech.json (ndjson or json)."""
from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: info_disclosure_extra_paths.py <tech.json> <out.txt>", file=sys.stderr)
        return 2
    tech_path, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    try:
        blob = tech_path.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        out_path.write_text("")
        return 0
    extra: list[str] = []
    if "wordpress" in blob or "wp-engine" in blob or "woocommerce" in blob:
        extra += [
            "/wp-login.php",
            "/xmlrpc.php",
            "/wp-json/",
            "/wp-admin/",
            "/wp-content/debug.log",
            "/wp-config.php.bak",
        ]
    if "laravel" in blob:
        extra += ["/.env.example", "/storage/logs/laravel.log", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]
    if "django" in blob:
        extra += ["/admin/", "/static/admin/"]
    if "spring" in blob or "tomcat" in blob:
        extra += ["/actuator", "/actuator/health", "/manager/html"]
    if "next.js" in blob or "nextjs" in blob:
        extra += ["/_next/static/", "/api/"]
    seen: set[str] = set()
    lines = []
    for p in extra:
        if p not in seen:
            seen.add(p)
            lines.append(p)
    out_path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
