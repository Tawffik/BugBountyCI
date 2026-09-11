#!/usr/bin/env python3
from pathlib import Path
import re
import yaml

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

start = c.find("              body=$(proxychains4 -q curl -sk --max-time 12")
end = c.find("            done < /tmp/html_scrape_hosts.txt")
if start < 0 or end < 0:
    raise SystemExit("markers %s %s" % (start, end))

new_block = """              body=$(proxychains4 -q curl -sk --max-time 12 -H \"User-Agent: $SCAN_USER_AGENT\" \"$page\" 2>/dev/null || true)
              [ -n \"$body\" ] || body=$(curl -sk --max-time 10 -H \"User-Agent: $SCAN_USER_AGENT\" \"$page\" 2>/dev/null || true)
              [ -n \"$body\" ] || continue
              # Safe extract (run#14: nested quotes caused exit 2 syntax error)
              printf '%s\\n' \"$body\" | grep -oE 'https?://[^ ]+' >> \"$RD/urls/html_extract.txt\" 2>/dev/null || true
              printf '%s\\n' \"$body\" | grep -oiE 'src=/[^ >]+' | sed 's/^[Ss][Rr][Cc]=//' | while IFS= read -r ref; do
                [ -z \"$ref\" ] && continue
                echo \"${page%/}$ref\"
              done >> \"$RD/urls/html_extract.txt\" 2>/dev/null || true
"""

c = c[:start] + new_block + c[end:]
print("OK html")

c2, n = re.subn(
    r'(name: "🔎 Content Discovery Fuzzing"\n        continue-on-error: true\n        )timeout-minutes: 20',
    r'\1timeout-minutes: 25',
    c,
    count=1,
)
c = c2
print("timeout", n)

idx = c.find('FUZZ_INPUT="$RD/live/expensive_targets.txt"')
if idx >= 0:
    region = c[idx:idx+900]
    region2 = (region.replace("echo 1400", "echo 900", 1)
                     .replace("echo 300", "echo 240", 1)
                     .replace("echo 700", "echo 500", 1)
                     .replace("per_host=90", "per_host=60", 1))
    c = c[:idx] + region2 + c[idx+900:]
    print("OK ffuf")
else:
    print("SKIP ffuf")

yaml.safe_load(c)
p.write_text(c)
print("DONE", len(c.splitlines()))
