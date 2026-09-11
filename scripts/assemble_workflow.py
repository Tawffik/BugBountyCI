#!/usr/bin/env python3
"""Assemble zero-track-hunter.yml from gzip+base64 parts."""
import base64, gzip
from pathlib import Path
root = Path(__file__).resolve().parents[1]
parts_dir = root / ".github" / "workflows" / "_payload"
parts = sorted(parts_dir.glob("part_*.b64"), key=lambda p: int(p.stem.split("_")[1]))
assert parts, f"no parts in {parts_dir}"
b64 = "".join(p.read_text().strip() for p in parts)
raw = gzip.decompress(base64.b64decode(b64))
out = root / ".github" / "workflows" / "zero-track-hunter.yml"
out.write_bytes(raw)
print(f"wrote {out} ({len(raw)} bytes) from {len(parts)} parts")
