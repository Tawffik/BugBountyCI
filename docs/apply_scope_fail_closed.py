#!/usr/bin/env python3
"""#1 Scope fail-closed + target format validation."""
from pathlib import Path

p = Path(".github/workflows/zero-track-hunter.yml")
text = p.read_text()
assert "PLACEHOLDER" not in text and "Final all.txt" in text

if "scope.txt is missing. Refusing to run (fail-closed)" in text:
    print("already applied")
    raise SystemExit(0)

start = text.find('      - name: "🔒 Verify Target Is In Authorized Scope"')
end = text.find('      - name: "✅ Environment Validation"', start)
if start < 0 or end < 0:
    raise SystemExit("scope step markers not found")

new_block = r'''      - name: "🔒 Verify Target Is In Authorized Scope"
        # FAIL-CLOSED: missing scope.txt or invalid/out-of-scope target stops the job.
        # continue-on-error must stay OFF — this gates active/exploit phases.
        env:
          TARGET_INPUT: ${{ inputs.target }}
        run: |
          set -euo pipefail
          target="$(echo "${TARGET_INPUT}" | xargs)"
          target="${target%/}"
          if [[ "$target" == http://* || "$target" == https://* ]]; then
            echo "::error::Target must be a bare domain (e.g. example.com), not a URL: '$target'"
            exit 1
          fi
          if [[ "$target" == */* ]]; then
            echo "::error::Target must not contain a path: '$target'"
            exit 1
          fi
          if [[ "$target" =~ [[:space:]] ]] || [[ "$target" =~ [\;\|\&\$\`\(\)\{\}\<\>\'\"\!] ]]; then
            echo "::error::Target contains forbidden characters: '$target'"
            exit 1
          fi
          if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "::error::Target must be a domain name, not an IP address: '$target'"
            exit 1
          fi
          if [[ "$target" == \** ]]; then
            echo "::error::Target must be a concrete domain (example.com), not a wildcard pattern: '$target'"
            exit 1
          fi
          target_lower="$(echo "$target" | tr '[:upper:]' '[:lower:]')"
          if [[ ! "$target_lower" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
            echo "::error::Target is not a valid domain name: '$target'"
            exit 1
          fi
          if [[ ! -f "scope.txt" ]]; then
            echo "::error::scope.txt is missing. Refusing to run (fail-closed)."
            echo "   Create scope.txt in the repo root with one authorized domain or *.domain per line."
            echo "   See scope.txt.example for the format."
            exit 1
          fi
          if [[ ! -s "scope.txt" ]]; then
            echo "::error::scope.txt exists but is empty. Add at least one authorized domain."
            exit 1
          fi
          matched=0
          while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
            line="${raw_line%%#*}"; line="$(echo "$line" | xargs)"
            [[ -z "$line" ]] && continue
            ll="$(echo "$line" | tr '[:upper:]' '[:lower:]')"
            if [[ "$ll" == "$target_lower" ]]; then matched=1; break; fi
            if [[ "$ll" == \*.* ]]; then
              base="${ll:2}"
              if [[ "$target_lower" == *".$base" || "$target_lower" == "$base" ]]; then matched=1; break; fi
            fi
          done < scope.txt
          if [[ "$matched" != "1" ]]; then
            echo "::error::'$target' is NOT listed in scope.txt. Refusing to run against an unauthorized target."
            echo "   Add '$target' or a matching '*.parent.tld' entry to scope.txt, then re-run."
            exit 1
          fi
          echo "✅ Target authorized: $target_lower (matched scope.txt)"
          echo "TARGET=$target_lower" >> "$GITHUB_ENV"

'''

text = text[:start] + new_block + text[end:]
assert "Final all.txt" in text and "gospider" in text
p.write_text(text)
print("OK", len(text.splitlines()))
