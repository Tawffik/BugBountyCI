#!/usr/bin/env python3
from pathlib import Path
import re
import yaml
import subprocess

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

old = '''timeout 120 proxychains4 -q gospider -S "$GS_LIST" -t 10 -d 2 --js --sitemap --robots -a -w -c 10 2>>"$RD/logs/gospider.log"             | grep -Eo "https?://[^[:space:]"]+" | sort -u > "$RD/urls/gospider.txt" || true'''
new = '''timeout 120 proxychains4 -q gospider -S "$GS_LIST" -t 10 -d 2 --js --sitemap --robots -a -w -c 10 2>>"$RD/logs/gospider.log" | grep -Eo 'https?://[^[:space:]]+' | sort -u > "$RD/urls/gospider.txt" || true'''
if old not in c:
    raise SystemExit("gospider line not found")
c = c.replace(old, new, 1)
print("OK gospider")

if 'Final all.txt: $(wc -l < "$RD/urls/all.txt" 2>/dev/null || echo 0) URLs\n' in c:
    c = c.replace(
        'Final all.txt: $(wc -l < "$RD/urls/all.txt" 2>/dev/null || echo 0) URLs\n',
        'Final all.txt: $(wc -l < "$RD/urls/all.txt" 2>/dev/null || echo 0) URLs"\n',
        1,
    )
    print("OK Final all.txt quote")
elif 'Final all.txt: $(wc -l < "$RD/urls/all.txt" 2>/dev/null || echo 0) URLs"' in c:
    print("SKIP Final already quoted")
else:
    print("WARN Final pattern")

yaml.safe_load(c)
p.write_text(c)

lines = c.splitlines()
start = end = None
for i, line in enumerate(lines):
    if 'name: "📜 URL Collection"' in line:
        start = i
    if start is not None and 'name: "📦 JavaScript Analysis"' in line:
        end = i
        break
block = []
in_run = False
for i in range(start, end):
    line = lines[i]
    if line.strip().startswith('run:'):
        in_run = True
        continue
    if in_run:
        if line.startswith('          '):
            block.append(line[10:])
        elif line.strip() == '':
            block.append('')
script = "\n".join(block)
script = script.replace("${{ env.TARGET }}", "example.com")
script = script.replace("${{ env.TIMESTAMP }}", "1")
script = re.sub(r'\$\{\{[^}]+\}\}', 'x', script)
Path("/tmp/url_check.sh").write_text(script)
r = subprocess.run(["bash", "-n", "/tmp/url_check.sh"], capture_output=True, text=True)
print("bash -n", r.returncode)
if r.returncode != 0:
    print(r.stderr)
    raise SystemExit("bash syntax still broken")
print("DONE", len(c.splitlines()))
