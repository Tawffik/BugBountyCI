#!/usr/bin/env python3
"""Fix duplicated asnmap if nesting from double-apply."""
from pathlib import Path
import yaml

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

broken = '''            timeout 45 asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true
            if [ ! -s /tmp/asn_cidrs.txt ]; then
              echo "⚠️ asnmap DIRECT empty — trying Tor..."
              timeout 45 asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true
            if [ ! -s /tmp/asn_cidrs.txt ]; then
              echo "⚠️ asnmap DIRECT empty — trying Tor..."
              timeout 60 proxychains4 -q asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true
            fi
            fi'''

fixed = '''            timeout 45 asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true
            if [ ! -s /tmp/asn_cidrs.txt ]; then
              echo "⚠️ asnmap DIRECT empty — trying Tor..."
              timeout 60 proxychains4 -q asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true
            fi'''

if broken not in c:
    if fixed in c:
        print("asnmap already clean")
    else:
        raise SystemExit("broken asnmap pattern not found")
else:
    c = c.replace(broken, fixed, 1)
    print("asnmap block fixed")

yaml.safe_load(c)
p.write_text(c)
print("OK")
