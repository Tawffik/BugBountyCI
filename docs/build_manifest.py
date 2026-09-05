"""
PIPELINE_MANIFEST builder — extracts, for every step:
  - what it reads (input files)
  - what it writes (output files)
  - what env vars / functions it depends on (call_with_retry, tst(), etc)
This becomes the reference I check BEFORE editing anything, so I know the
blast radius of a change instead of guessing.
"""
import yaml, re

with open('current.yml') as f:
    data = yaml.safe_load(f)
steps = data['jobs']['full_scan']['steps']

read_re = re.compile(r'\$RD/([A-Za-z0-9_./\-]+\.(?:txt|json|jsonl|csv|log|md))')
write_hint_re = re.compile(r'(-o[a-zA-Z]*\s+["\']?\$RD|--output\s+["\']?\$RD|>\s*["\']?\$RD|-oT\s+["\']?\$RD|open\(os\.path\.join\(rd)')

manifest_lines = ["# PIPELINE_MANIFEST.md", "", "Auto-generated reference — regenerate after structural edits.", ""]
for i, s in enumerate(steps):
    name = s.get('name', f'step_{i}')
    run = s.get('run', '')
    if not run:
        manifest_lines.append(f"## {i}. {name}  _(uses: {s.get('uses','-')})_")
        continue
    reads, writes = set(), set()
    for line in run.split('\n'):
        for m in read_re.finditer(line):
            p = m.group(1)
            (writes if write_hint_re.search(line) else reads).add(p)
    manifest_lines.append(f"## {i}. {name}")
    manifest_lines.append(f"- if: `{s.get('if','-')}`  timeout: {s.get('timeout-minutes','-')}m")
    if writes: manifest_lines.append(f"- **writes**: {', '.join(sorted(writes))}")
    if reads - writes: manifest_lines.append(f"- **reads**: {', '.join(sorted(reads - writes))}")
    manifest_lines.append("")

with open('PIPELINE_MANIFEST.md', 'w') as f:
    f.write('\n'.join(manifest_lines))
print(f"Manifest built: {len(steps)} steps documented")
