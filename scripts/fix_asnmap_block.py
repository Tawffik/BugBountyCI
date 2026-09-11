#!/usr/bin/env python3
"""Clean duplicated asnmap DIRECT/Tor if nesting."""
from pathlib import Path
import re
import yaml

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

# Match any corrupted nested-if variant after first DIRECT call
pat = re.compile(
    r'(timeout 45 asnmap -d "\$\{\{ env\.TARGET \}\}" -silent -o /tmp/asn_cidrs\.txt 2>>"\$RD/logs/asnmap\.log" \|\| true\n)'
    r'(?:\s*if \[ ! -s /tmp/asn_cidrs\.txt \]; then\n'
    r'\s*echo "⚠️ asnmap DIRECT empty — trying Tor\.\.\."\n'
    r'\s*timeout (?:45|60) (?:proxychains4 -q )?asnmap -d "\$\{\{ env\.TARGET \}\}" -silent -o /tmp/asn_cidrs\.txt 2>>"\$RD/logs/asnmap\.log" \|\| true\n)'
    r'+'
    r'(?:\s*fi\n)+',
    re.MULTILINE,
)

fixed = (
    'timeout 45 asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true\n'
    '            if [ ! -s /tmp/asn_cidrs.txt ]; then\n'
    '              echo "⚠️ asnmap DIRECT empty — trying Tor..."\n'
    '              timeout 60 proxychains4 -q asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true\n'
    '            fi\n'
)

new_c, n = pat.subn(fixed, c, count=1)
if n == 0:
    if 'asnmap DIRECT empty — trying Tor' in c and c.count('asnmap DIRECT empty') == 1:
        print('asnmap already clean')
    else:
        # fallback exact broken block
        broken = (
            'timeout 45 asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true\n'
            '            if [ ! -s /tmp/asn_cidrs.txt ]; then\n'
            '              echo "⚠️ asnmap DIRECT empty — trying Tor..."\n'
            '              timeout 45 asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true\n'
            '            if [ ! -s /tmp/asn_cidrs.txt ]; then\n'
            '              echo "⚠️ asnmap DIRECT empty — trying Tor..."\n'
            '              timeout 60 proxychains4 -q asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true\n'
            '            fi\n'
            '            fi'
        )
        if broken in c:
            c = c.replace(broken, fixed.rstrip('\n'), 1)
            print('asnmap fixed via exact broken block')
            new_c = c
            n = 1
        else:
            raise SystemExit('could not match asnmap block')
else:
    print('asnmap fixed via regex, replacements=', n)
    c = new_c

yaml.safe_load(c)
p.write_text(c)
print('DONE count DIRECT msgs=', c.count('asnmap DIRECT empty'))
