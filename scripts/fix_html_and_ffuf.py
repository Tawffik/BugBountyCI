#!/usr/bin/env python3
"""Fix run#14: HTML extract bash syntax error + ffuf budget > step timeout."""
from pathlib import Path
import re
import yaml

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

start = c.find('              body=$(proxychains4 -q curl -sk --max-time 12')
end = c.find('            done < /tmp/html_scrape_hosts.txt')
if start < 0 or end < 0:
    raise SystemExit('html markers not found')

# Pure bash/grep — no nested quote hell, no heredoc (YAML-safe)
new_block = '''              body=$(proxychains4 -q curl -sk --max-time 12 -H "User-Agent: $SCAN_USER_AGENT" "$page" 2>/dev/null || true)
              [ -n "$body" ] || body=$(curl -sk --max-time 10 -H "User-Agent: $SCAN_USER_AGENT" "$page" 2>/dev/null || true)
              [ -n "$body" ] || continue
              # Safe extract (run#14: nested bash quotes caused syntax error near )
              printf '%s\n' "$body" | grep -oE 'https?://[^\"\\'\\" <>]+' >> "$RD/urls/html_extract.txt" 2>/dev/null || true
              printf '%s\n' "$body" | grep -oE 'src=[^ >]+' | sed 's/^src=//;s/[\"\\'\\"]//g' | while IFS= read -r ref; do
                [ -z "$ref" ] && continue
                case "$ref" in
                  http://*|https://*) echo "$ref" ;;
                  //*) echo "https:$ref" ;;
                  /*) echo "${page%/}$ref" ;;
                  *) echo "${page}${ref}" ;;
                esac
              done >> "$RD/urls/html_extract.txt" 2>/dev/null || true
              printf '%s\n' "$body" | grep -oE '[^ \"\\'\\"]+\\.js([?][^ \"\\'\\"]*)?' | while IFS= read -r ref; do
                [ -z "$ref" ] && continue
                case "$ref" in
                  http://*|https://*) echo "$ref" ;;
                  //*) echo "https:$ref" ;;
                  /*) echo "${page%/}$ref" ;;
                  *) echo "${page}${ref}" ;;
                esac
              done >> "$RD/urls/html_extract.txt" 2>/dev/null || true
'''

c = c[:start] + new_block + c[end:]
print('OK: html extract')

# Content Discovery Fuzzing: raise step timeout and lower budgets so budget < step
c, n = re.subn(
    r'(name: "🔎 Content Discovery Fuzzing"\n        continue-on-error: true\n        )timeout-minutes: 20',
    r'\1timeout-minutes: 25',
    c,
    count=1,
)
print('timeout-minutes', 'OK' if n else 'SKIP')

# Only the ffuf block near Content Discovery — unique context
old_b = '''            mode="${HUNTING_MODE:-normal}"
            budget=$({ [ "$mode" = "light" ] && echo 300; } || { [ "$mode" = "aggressive" ] && echo 1400; } || echo 700)
            total=$(wc -l < "$FUZZ_INPUT")
            per_host=90'''
new_b = '''            mode="${HUNTING_MODE:-normal}"
            # budgets MUST stay under step timeout-minutes (25m=1500s); leave headroom
            budget=$({ [ "$mode" = "light" ] && echo 240; } || { [ "$mode" = "aggressive" ] && echo 900; } || echo 500)
            total=$(wc -l < "$FUZZ_INPUT")
            per_host=60'''
if old_b in c:
    c = c.replace(old_b, new_b, 1)
    print('OK: ffuf budget')
else:
    print('SKIP: ffuf budget exact block')
    if 'echo 1400' in c:
        # last resort one replace only inside fuzz section by unique FUZZ_INPUT context
        idx = c.find('FUZZ_INPUT="$RD/live/expensive_targets.txt"')
        if idx > 0:
            chunk = c[idx:idx+800]
            chunk2 = chunk.replace('echo 1400', 'echo 900').replace('echo 300', 'echo 240').replace('echo 700', 'echo 500').replace('per_host=90', 'per_host=60')
            c = c[:idx] + chunk2 + c[idx+800:]
            print('OK: ffuf budget via chunk')

yaml.safe_load(c)
p.write_text(c)
print('DONE', len(c.splitlines()))
