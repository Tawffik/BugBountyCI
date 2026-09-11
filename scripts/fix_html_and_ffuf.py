#!/usr/bin/env python3
"""Fix remaining run#14 issues visible in screenshots:
1) URL Collection exit 2: fragile nested quotes in HTML JS extract
2) Content Discovery step timeout: internal budget 1400s > step 20m
"""
from pathlib import Path
import re
import yaml

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

# --- 1) Replace the whole HTML scrape while-loop body extraction with safe python ---
old = '''              body=$(proxychains4 -q curl -sk --max-time 12 -H "User-Agent: $SCAN_USER_AGENT" "$page" 2>/dev/null || true)
              [ -n "$body" ] || body=$(curl -sk --max-time 10 -H "User-Agent: $SCAN_USER_AGENT" "$page" 2>/dev/null || true)
              [ -n "$body" ] || continue
              # script src, link href, and quoted .js / api paths
              echo "$body" | grep -oE '(src|href)=["''' + "'" + r''''][^"''' + "'" + r''']+' 2>/dev/null \
                | sed -E 's/^(src|href)=["''' + "'" + r''']//' | while IFS= read -r ref; do
                    case "$ref" in
                      http://*|https://*) echo "$ref" ;;
                      //*) echo "https:$ref" ;;
                      /*) echo "${page%/}$ref" ;;
                      *) echo "${page}${ref}" ;;
                    esac
                  done >> "$RD/urls/html_extract.txt" || true
              echo "$body" | grep -oE '["''' + "'" + r'''][^"''' + "'" + r''']+\.js(\?[^"''' + "'" + r''']*)?["''' + "'" + r''']' 2>/dev/null \
                | tr -d '"''' + "'" + r''' | while IFS= read -r ref; do
                    case "$ref" in
                      http://*|https://*) echo "$ref" ;;
                      //*) echo "https:$ref" ;;
                      /*) echo "${page%/}$ref" ;;
                      *) echo "${page}${ref}" ;;
                    esac
                  done >> "$RD/urls/html_extract.txt" || true'''

# Simpler approach: find marker lines and replace between them
start = c.find('              body=$(proxychains4 -q curl -sk --max-time 12')
end = c.find('            done < /tmp/html_scrape_hosts.txt')
if start < 0 or end < 0:
    print('SKIP html: markers not found', start, end)
else:
    new_block = r'''              body=$(proxychains4 -q curl -sk --max-time 12 -H "User-Agent: $SCAN_USER_AGENT" "$page" 2>/dev/null || true)
              [ -n "$body" ] || body=$(curl -sk --max-time 10 -H "User-Agent: $SCAN_USER_AGENT" "$page" 2>/dev/null || true)
              [ -n "$body" ] || continue
              # Safe extract (no nested bash quotes — run#14 died with syntax error near ) )
              PAGE_BASE="$page" BODY_TMP=/tmp/html_body_$$.txt
              printf '%s' "$body" > "$BODY_TMP"
              python3 - "$PAGE_BASE" "$BODY_TMP" >> "$RD/urls/html_extract.txt" <<'PY'
import re, sys
page, path = sys.argv[1], sys.argv[2]
try:
    body = open(path, errors='ignore').read()
except Exception:
    sys.exit(0)
base = page if page.endswith('/') else page + '/'
root = page.rstrip('/')
out = []
for ref in re.findall(r'(?:src|href)=["\']([^"\']+)', body, re.I):
    if ref.startswith(('http://', 'https://')):
        out.append(ref)
    elif ref.startswith('//'):
        out.append('https:' + ref)
    elif ref.startswith('/'):
        out.append(root + ref)
    else:
        out.append(base + ref)
for ref in re.findall(r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body, re.I):
    if ref.startswith(('http://', 'https://')):
        out.append(ref)
    elif ref.startswith('//'):
        out.append('https:' + ref)
    elif ref.startswith('/'):
        out.append(root + ref)
    else:
        out.append(base + ref)
for u in out:
    print(u)
PY
              rm -f "$BODY_TMP"
'''
    c = c[:start] + new_block + c[end:]
    print('OK: html extract rewritten')

# --- 2) ffuf: budget must fit inside timeout-minutes ---
# aggressive was 1400s but step is 20m=1200s → always step-timeout
c2, n = re.subn(
    r'(name: "🔎 Content Discovery Fuzzing"\n\s+continue-on-error: true\n\s+)timeout-minutes: 20',
    r'\1timeout-minutes: 25',
    c,
    count=1,
)
if n:
    c = c2
    print('OK: content discovery step timeout 25m')
else:
    print('SKIP: content discovery timeout-minutes')

c2, n = re.subn(
    r'budget=\$\(\{ \[ "\$mode" = "light" \] && echo 300; \} \|\| \{ \[ "\$mode" = "aggressive" \] && echo 1400; \} \|\| echo 700\)',
    r'budget=$({ [ "$mode" = "light" ] && echo 240; } || { [ "$mode" = "aggressive" ] && echo 900; } || echo 500)',
    c,
    count=1,
)
if n:
    c = c2
    print('OK: ffuf budgets reduced under step limit')
else:
    # try looser
    if 'echo 1400' in c and 'Content Discovery' in c:
        c = c.replace('echo 1400', 'echo 900', 1)
        c = c.replace(
            'budget=$({ [ "$mode" = "light" ] && echo 300; } || { [ "$mode" = "aggressive" ] && echo 900; } || echo 700)',
            'budget=$({ [ "$mode" = "light" ] && echo 240; } || { [ "$mode" = "aggressive" ] && echo 900; } || echo 500)',
            1,
        )
        print('OK: ffuf budget 1400->900 fallback')
    else:
        print('SKIP: ffuf budget pattern')

yaml.safe_load(c)
p.write_text(c)
print('DONE lines', len(c.splitlines()))
