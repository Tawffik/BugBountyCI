#!/usr/bin/env python3
from pathlib import Path
p = Path(".github/workflows/zero-track-hunter.yml")
t = p.read_text()
assert "Final all.txt" in t
old = (
    "          confirmed.sort(key=lambda x: -x[0])\n\n"
    "          # Recon leads - NOT confirmed vulnerabilities, just worth a human looking at\n"
    "          leads = []\n"
    '          for l in rl("js/github_recon.txt"): leads.append(("GitHub Exposure", l))'
)
new = (
    "          confirmed.sort(key=lambda x: -x[0])\n\n"
    "          # Recon leads - keep leads already added (origin/path/IDOR/GraphQL)\n"
    "          if not isinstance(leads, list):\n"
    "              leads = []\n"
    '          for l in rl("js/github_recon.txt"): leads.append(("GitHub Exposure", l))'
)
if "keep leads already added" in t:
    print("already")
elif old not in t:
    raise SystemExit("block missing")
else:
    t = t.replace(old, new, 1)
    p.write_text(t)
    print("leads wipe fixed")
assert "Final all.txt" in t
