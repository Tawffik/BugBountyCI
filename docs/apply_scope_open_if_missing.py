#!/usr/bin/env python3
"""If scope.txt missing/empty → continue; if present with entries → enforce."""
from pathlib import Path

p = Path(".github/workflows/zero-track-hunter.yml")
text = p.read_text()
assert "Final all.txt" in text

if "continuing without allow-list (open mode)" in text:
    print("already applied")
    raise SystemExit(0)

old = '''          if [[ ! -f "scope.txt" ]]; then
            echo "::error::scope.txt is missing. Refusing to run (fail-closed)."
            echo "   Create scope.txt in the repo root with one authorized domain or *.domain per line."
            echo "   See scope.txt.example for the format."
            exit 1
          fi
          if [[ ! -s "scope.txt" ]]; then
            echo "::error::scope.txt exists but is empty. Add at least one authorized domain."
            exit 1
          fi
          matched=0'''

new = '''          # Missing/empty scope.txt → continue with warning (open mode).
          # Non-empty scope.txt → enforce allow-list.
          if [[ ! -f "scope.txt" ]] || [[ ! -s "scope.txt" ]]; then
            echo "⚠️ No scope.txt (or empty) — continuing without allow-list (open mode)."
            echo "   Optional: add scope.txt (see scope.txt.example) to restrict targets."
            echo "✅ Target format OK: $target_lower (no scope file to match)"
            echo "TARGET=$target_lower" >> "$GITHUB_ENV"
            exit 0
          fi
          matched=0'''

if old not in text:
    raise SystemExit("fail-closed scope block not found")
text = text.replace(old, new, 1)
text = text.replace(
    "# FAIL-CLOSED: missing scope.txt or invalid/out-of-scope target stops the job.",
    "# Format validation always on. Missing scope.txt = open mode. Non-empty scope = enforce allow-list.",
    1,
)
assert "Final all.txt" in text
p.write_text(text)
print("OK", len(text.splitlines()))
