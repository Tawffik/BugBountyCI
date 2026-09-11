#!/usr/bin/env python3
"""Add gospider simply - soft-fail, timeout, expensive_targets only."""
from pathlib import Path
import yaml

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

if "urls/gospider.txt" in c:
    print("gospider already present")
    raise SystemExit(0)

# install after hakrawler
inst = "          install_if_missing hakrawler go install github.com/hakluke/hakrawler@latest\n"
if inst not in c:
    raise SystemExit("hakrawler install marker missing")
c = c.replace(
    inst,
    inst + "          install_if_missing gospider go install github.com/jaeles-project/gospider@latest\n",
    1,
)
print("OK: install")

# touch list
old_touch = 'touch "$RD/urls/wayback.txt" "$RD/urls/wayback_js.txt" "$RD/urls/gau.txt" "$RD/urls/katana.txt" "$RD/urls/hakrawler.txt" "$RD/urls/urlscan.txt" "$RD/urls/otx.txt" "$RD/urls/html_extract.txt" "$RD/urls/robots_sitemap.txt" "$RD/urls/juicy.txt"'
new_touch = 'touch "$RD/urls/wayback.txt" "$RD/urls/wayback_js.txt" "$RD/urls/gau.txt" "$RD/urls/katana.txt" "$RD/urls/hakrawler.txt" "$RD/urls/gospider.txt" "$RD/urls/urlscan.txt" "$RD/urls/otx.txt" "$RD/urls/html_extract.txt" "$RD/urls/robots_sitemap.txt" "$RD/urls/juicy.txt"'
if old_touch not in c:
    raise SystemExit("touch marker missing")
c = c.replace(old_touch, new_touch, 1)
print("OK: touch")

# run after hakrawler echo block ends - after hakrawler.txt handling
marker = '          echo "🔍 urlscan.io passive (often works when archive.org rate-limits GitHub runner IPs)..."\n'
run = (
    '          echo "🔍 Gospider..."\n'
    '          : > "$RD/urls/gospider.txt"\n'
    '          GS_LIST="$RD/live/expensive_targets.txt"; [ -s "$GS_LIST" ] || GS_LIST="$RD/live/scan_order.txt"; [ -s "$GS_LIST" ] || GS_LIST="$RD/live/live.txt"\n'
    '          if command -v gospider >/dev/null 2>&1 && [ -s "$GS_LIST" ]; then\n'
    '            timeout 120 proxychains4 -q gospider -S "$GS_LIST" -t 10 -d 2 --js --sitemap --robots -a -w -c 10 2>>"$RD/logs/gospider.log" '
    '            | grep -Eo "https?://[^[:space:]\"]+" | sort -u > "$RD/urls/gospider.txt" || true\n'
    '          else\n'
    '            echo "⚠️ gospider skipped"\n'
    '          fi\n'
    '          echo "ℹ️ gospider: $(wc -l < "$RD/urls/gospider.txt" 2>/dev/null || echo 0)"\n'
    + marker
)
if marker not in c:
    raise SystemExit("urlscan marker missing")
c = c.replace(marker, run, 1)
print("OK: run")

# merge sources
old_m = 'for src in wayback wayback_js gau katana hakrawler urlscan otx html_extract robots_sitemap; do'
new_m = 'for src in wayback wayback_js gau katana hakrawler gospider urlscan otx html_extract robots_sitemap; do'
if old_m not in c:
    raise SystemExit("merge marker missing")
c = c.replace(old_m, new_m, 1)
print("OK: merge")

yaml.safe_load(c)
p.write_text(c)
print("DONE", len(c.splitlines()))
