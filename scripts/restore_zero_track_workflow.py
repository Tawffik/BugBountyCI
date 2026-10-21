#!/usr/bin/env python3
"""Restore zero-track-hunter.yml from gzip+base64 small parts."""
from __future__ import annotations
import base64, gzip, sys
from pathlib import Path
parts_dir = Path("scripts/rrp/wf_parts")
out = Path(".github/workflows/zero-track-hunter.yml")
files = sorted(parts_dir.glob("b64_*.txt"))
if not files:
    print("no b64 parts", file=sys.stderr)
    sys.exit(1)
b64 = "".join(f.read_text().strip() for f in files)
raw = gzip.decompress(base64.b64decode(b64))
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(raw)
text = raw.decode("utf-8")
print(f"wrote {out} ({len(raw)} bytes) from {len(files)} parts")
assert "EMPTY_VALID" in text and "sync_pipeline_health_md.py" in text and "Zero Track" in text
print("sanity OK")
