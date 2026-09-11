#!/usr/bin/env python3
"""Add ProjectDiscovery chaos client (uses existing PDCP_API_KEY).

Soft-fail only. Does not touch uro/asnmap/findomain patches.
"""
from pathlib import Path
import yaml

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

if "subdomains/chaos.txt" in c:
    print("chaos already present")
    raise SystemExit(0)

# 1) install near asnmap
inst = "          install_if_missing asnmap    go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest\n"
if inst not in c:
    raise SystemExit("asnmap install marker not found")
c = c.replace(
    inst,
    inst
    + "          install_if_missing chaos     go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest\n",
    1,
)
print("OK: chaos install")

# 2) run after findomain block if present, else after crt.sh
anchor = '          echo "ℹ️ findomain: $(wc -l < "$RD/subdomains/findomain.txt" 2>/dev/null || echo 0)"\n'
block = (
    '          echo "🔍 Chaos (ProjectDiscovery passive dataset)..."\n'
    '          : > "$RD/subdomains/chaos.txt"\n'
    '          if [ -n "${{ env.PDCP_API_KEY }}" ] && command -v chaos >/dev/null 2>&1; then\n'
    '            export PDCP_API_KEY="${{ env.PDCP_API_KEY }}"\n'
    '            timeout 120 chaos -d "$TARGET" -silent -o "$RD/subdomains/chaos.txt" 2>>"$RD/logs/chaos.log" || true\n'
    '          else\n'
    '            echo "⚠️ chaos skipped (missing PDCP_API_KEY or binary)"\n'
    '          fi\n'
    '          echo "ℹ️ chaos: $(wc -l < "$RD/subdomains/chaos.txt" 2>/dev/null || echo 0)"\n'
)

if anchor in c:
    c = c.replace(anchor, anchor + block, 1)
    print("OK: chaos run after findomain")
else:
    crt = (
        '          curl -s --max-time 30 "https://crt.sh/?q=%25.${TARGET}&output=json" | jq -r \'.[].name_value\' 2>/dev/null | tr \',\' \'\n\' | sed \'s/^\\*\.//\' | sort -u > "$RD/subdomains/crtsh.txt" 2>/dev/null || true\n'
    )
    # simpler search
    idx = c.find('echo "🔍 Amass (passive')
    if idx < 0:
        raise SystemExit("amass marker not found")
    c = c[:idx] + block + c[idx:]
    print("OK: chaos run before amass")

# 3) optional verify list mentions chaos (non-fatal)
# merge already uses subdomains/*.txt

yaml.safe_load(c)
p.write_text(c)
print("DONE lines", len(c.splitlines()))
