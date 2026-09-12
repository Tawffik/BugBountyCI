#!/usr/bin/env python3
"""Fix YAML-breaking tr -d with a real newline inside quotes (must be \\r)."""
from pathlib import Path

p = Path(".github/workflows/zero-track-hunter.yml")
t = p.read_text()
assert "Final all.txt" in t

fixed = 0
out = []
i = 0
while i < len(t):
    j = t.find("tr -d '", i)
    if j < 0:
        out.append(t[i:])
        break
    out.append(t[i:j])
    q = j + len("tr -d '")
    if q < len(t) and t[q] == "\n" and q + 1 < len(t) and t[q + 1] == "'":
        out.append("tr -d '\\r'")
        i = q + 2
        fixed += 1
    else:
        out.append(t[j:q])
        i = q

t2 = "".join(out)
if fixed == 0:
    print("already clean")
    raise SystemExit(0)

if "YAML_TR_CR_FIX" not in t2:
    t2 = t2.replace(
        "BUDGET_REDIST_2026_09:",
        "YAML_TR_CR_FIX + BUDGET_REDIST_2026_09:",
        1,
    )

assert "Final all.txt" in t2
assert "Canonical findings schema" in t2
p.write_text(t2)
print("fixed", fixed, "lines", len(t2.splitlines()))
