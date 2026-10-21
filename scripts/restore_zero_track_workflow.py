#!/usr/bin/env python3
"""Concatenate scripts/rrp/wf_parts/part_*.txt into zero-track-hunter.yml."""
from pathlib import Path
import sys
parts_dir = Path("scripts/rrp/wf_parts")
out = Path(".github/workflows/zero-track-hunter.yml")
files = sorted(parts_dir.glob("part_*.txt"))
if not files:
    print("no parts found", file=sys.stderr)
    sys.exit(1)
text = "".join(f.read_text() for f in files)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(text)
print(f"wrote {out} ({len(text)} bytes) from {len(files)} parts")
assert "EMPTY_VALID" in text
assert "sync_pipeline_health_md.py" in text
assert "Zero Track" in text
print("sanity OK")
