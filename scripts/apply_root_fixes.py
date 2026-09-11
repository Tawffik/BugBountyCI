#!/usr/bin/env python3
"""Apply superdrug#14 root-cause fixes to zero-track-hunter.yml"""
from pathlib import Path

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

# Fix 1: uro empty wipe
needle = (
    'timeout 90 uro < /tmp/urls_merged.txt > "$RD/urls/all.txt" 2>/dev/null '
    '|| cp /tmp/urls_merged.txt "$RD/urls/all.txt"\n'
    '          echo "✅ Total URLs: $(wc -l < "$RD/urls/all.txt")"'
)
if needle not in c:
    raise SystemExit("uro needle not found — abort")

replacement = """timeout 90 uro < /tmp/urls_merged.txt > /tmp/urls_uro.txt 2>/dev/null || true
          if [ -s /tmp/urls_uro.txt ]; then
            cp /tmp/urls_uro.txt \"$RD/urls/all.txt\"
            echo \"✅ Total URLs after uro: $(wc -l < \"$RD/urls/all.txt\")\"
          else
            cp /tmp/urls_merged.txt \"$RD/urls/all.txt\"
            echo \"⚠️ uro empty — keeping merged URLs in all.txt: $(wc -l < \"$RD/urls/all.txt\")\"
          fi
          if [ ! -s \"$RD/urls/all.txt\" ] && [ -s /tmp/urls_merged.txt ]; then
            cp /tmp/urls_merged.txt \"$RD/urls/all.txt\"
            echo \"⚠️ Safety restore all.txt from merge\"
          fi
          echo \"✅ Final all.txt: $(wc -l < \"$RD/urls/all.txt\" 2>/dev/null || echo 0) URLs\""""

c = c.replace(needle, replacement, 1)
print("uro fix applied")

# Fix 2: explicit merge sources
old_cat = 'cat "$RD"/urls/*.txt 2>/dev/null | sort -u > /tmp/urls_merged.txt'
new_cat = (
    ': > /tmp/urls_merged.txt\n'
    '          for src in wayback wayback_js gau katana hakrawler urlscan otx html_extract robots_sitemap; do\n'
    '            f="$RD/urls/${src}.txt"\n'
    '            [ -s "$f" ] && cat "$f" >> /tmp/urls_merged.txt\n'
    '          done\n'
    '          sort -u -o /tmp/urls_merged.txt /tmp/urls_merged.txt 2>/dev/null || true'
)
if old_cat in c:
    c = c.replace(old_cat, new_cat, 1)
    print("merge sources fixed")
else:
    print("WARN: cat glob not found")

# Fix 3: asnmap DIRECT first (first Tor-only invocation only)
old_asn = 'timeout 60 proxychains4 -q asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true'
new_asn = (
    'timeout 45 asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true\n'
    '            if [ ! -s /tmp/asn_cidrs.txt ]; then\n'
    '              echo "⚠️ asnmap DIRECT empty — trying Tor..."\n'
    '              timeout 60 proxychains4 -q asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true\n'
    '            fi'
)
if old_asn not in c:
    raise SystemExit("asnmap line not found — abort")
c = c.replace(old_asn, new_asn, 1)
print("asnmap DIRECT applied")

p.write_text(c)
print("OK lines", len(c.splitlines()))

import yaml
yaml.safe_load(p.read_text())
print("YAML valid")
