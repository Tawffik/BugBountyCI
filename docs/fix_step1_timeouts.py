#!/usr/bin/env python3
from pathlib import Path
import re
p = Path(".github/workflows/zero-track-hunter.yml")
t = p.read_text()
assert "Final all.txt" in t
i = t.find("Nuclei Vulnerability Scan")
j = t.find("timeout-minutes: 75", i) if i >= 0 else -1
if j > 0 and j - i < 200 and "timeout-minutes: 40" not in t[i:i+300]:
    t = t[:j] + "timeout-minutes: 40" + t[j+len("timeout-minutes: 75"):]
    print("nuclei 40")
t, n = re.subn(r"(^        timeout-minutes: )25\b", r"\g<1>18", t, count=2, flags=re.M)
print("25->18", n)
p.write_text(t)
print("step1 ok")
