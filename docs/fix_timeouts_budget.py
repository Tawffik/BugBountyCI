#!/usr/bin/env python3
"""Redistribute step timeouts under the 358-min job ceiling.
Cut low-ROI long tails; give a bit more to steps that historically cut off.
Does NOT touch URL Collection timeout or URL pipeline body.
"""
from pathlib import Path
import re

p = Path(".github/workflows/zero-track-hunter.yml")
t = p.read_text()
assert "Final all.txt" in t and "PLACEHOLDER" not in t

if "BUDGET_REDIST_2026_09" in t:
    print("already")
    raise SystemExit(0)

def set_timeout_for_step(text, step_name_substr, new_mins):
    pattern = re.compile(
        r'(- name: "[^"]*' + re.escape(step_name_substr) + r'[^"]*"\n(?:        .*\n)*?        timeout-minutes: )(\d+)',
        re.MULTILINE,
    )
    m = pattern.search(text)
    if not m:
        raise SystemExit(f"step not found: {step_name_substr}")
    old = m.group(2)
    text = text[: m.start(2)] + str(new_mins) + text[m.end(2) :]
    print(f"  {step_name_substr}: {old} -> {new_mins}")
    return text

t = set_timeout_for_step(t, "Screenshots", 12)
t = set_timeout_for_step(t, "Nikto Scan", 10)
t = set_timeout_for_step(t, "Content Discovery Fuzzing", 14)
t = set_timeout_for_step(t, "Direct-to-Origin WAF Bypass", 12)
t = set_timeout_for_step(t, "Cloud Origin Discovery", 10)
t = set_timeout_for_step(t, "Information Disclosure Scan", 16)

t = t.replace(
    "timeout-minutes: 358  # GitHub-hosted: install tools from scratch",
    "timeout-minutes: 358  # GitHub-hosted: install tools from scratch\n    # BUDGET_REDIST_2026_09: screenshots/nikto/fuzz trimmed; direct-origin/cloud/info bumped",
    1,
)

assert "Final all.txt" in t
assert "Canonical findings schema" in t
assert "live/verified.txt" in t
m = re.search(r'URL Collection"\n(?:        .*\n)*?        timeout-minutes: (\d+)', t)
if not m or m.group(1) != "22":
    raise SystemExit(f"URL Collection timeout must stay 22, got {m.group(1) if m else None}")
p.write_text(t)
print("OK", len(t.splitlines()))
