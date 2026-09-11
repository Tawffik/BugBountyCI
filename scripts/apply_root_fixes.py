#!/usr/bin/env python3
"""Safe pipeline patches only - tested against 4e4b579 workflow.

1) uro must never wipe all.txt
2) explicit URL source merge (not urls/*.txt)
3) asnmap DIRECT first
4) methodology URL classification (grep-only)
"""
from pathlib import Path
import yaml

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

def must_replace(old, new, label, count=1):
    global c
    if old not in c:
        raise SystemExit("ABORT: %s pattern not found" % label)
    c = c.replace(old, new, count)
    print("OK:", label)

# 1) uro safety
needle = (
    'timeout 90 uro < /tmp/urls_merged.txt > "$RD/urls/all.txt" 2>/dev/null '
    '|| cp /tmp/urls_merged.txt "$RD/urls/all.txt"\n'
    '          echo "✅ Total URLs: $(wc -l < "$RD/urls/all.txt")"'
)
replacement = (
    'timeout 90 uro < /tmp/urls_merged.txt > /tmp/urls_uro.txt 2>/dev/null || true\n'
    '          if [ -s /tmp/urls_uro.txt ]; then\n'
    '            cp /tmp/urls_uro.txt "$RD/urls/all.txt"\n'
    '            echo "✅ Total URLs after uro: $(wc -l < "$RD/urls/all.txt")"\n'
    '          else\n'
    '            cp /tmp/urls_merged.txt "$RD/urls/all.txt"\n'
    '            echo "⚠️ uro empty — keeping merged URLs in all.txt: $(wc -l < "$RD/urls/all.txt")"\n'
    '          fi\n'
    '          if [ ! -s "$RD/urls/all.txt" ] && [ -s /tmp/urls_merged.txt ]; then\n'
    '            cp /tmp/urls_merged.txt "$RD/urls/all.txt"\n'
    '            echo "⚠️ Safety restore all.txt from merge"\n'
    '          fi\n'
    '          echo "✅ Final all.txt: $(wc -l < "$RD/urls/all.txt" 2>/dev/null || echo 0) URLs'
)
must_replace(needle, replacement, "uro safety")

# 2) explicit merge
old_cat = 'cat "$RD"/urls/*.txt 2>/dev/null | sort -u > /tmp/urls_merged.txt'
new_cat = (
    ': > /tmp/urls_merged.txt\n'
    '          for src in wayback wayback_js gau katana hakrawler urlscan otx html_extract robots_sitemap; do\n'
    '            f="$RD/urls/${src}.txt"\n'
    '            [ -s "$f" ] && cat "$f" >> /tmp/urls_merged.txt\n'
    '          done\n'
    '          sort -u -o /tmp/urls_merged.txt /tmp/urls_merged.txt 2>/dev/null || true'
)
if old_cat in c:
    must_replace(old_cat, new_cat, "merge sources")
else:
    print("SKIP: merge")

# 3) asnmap DIRECT
old_asn = 'timeout 60 proxychains4 -q asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true'
new_asn = (
    'timeout 45 asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true\n'
    '            if [ ! -s /tmp/asn_cidrs.txt ]; then\n'
    '              echo "⚠️ asnmap DIRECT empty — trying Tor..."\n'
    '              timeout 60 proxychains4 -q asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true\n'
    '            fi'
)
if old_asn in c:
    must_replace(old_asn, new_asn, "asnmap DIRECT")
else:
    print("SKIP: asnmap")

# 4) methodology classification after juicy
juicy_echo = '          echo "✅ Juicy URLs (params/admin/api/config): $(wc -l < "$RD/urls/juicy.txt" 2>/dev/null || echo 0)"'
classify = (
    juicy_echo + '\n'
    '\n'
    '          # Methodology classification (grep-only, no new tools)\n'
    '          if [ -s "$RD/urls/all.txt" ]; then\n'
    "            grep -iE '\\.js(\\?|#|$)' \"$RD/urls/all.txt\" | grep -ivE '\\.json' | sort -u > \"$RD/urls/js_urls.txt\" || true\n"
    "            grep -iE '\\.(json|xml|graphql|gql)(\\?|#|$)|/graphql|/api/v[0-9]' \"$RD/urls/all.txt\" | sort -u > \"$RD/urls/api_urls.txt\" || true\n"
    "            grep -iE 'login|signin|auth|oauth|reset|password|sso' \"$RD/urls/all.txt\" | sort -u > \"$RD/urls/login_flows.txt\" || true\n"
    "            grep -iE 'admin|dashboard|internal|manage|console|panel' \"$RD/urls/all.txt\" | sort -u > \"$RD/urls/admin_panels.txt\" || true\n"
    "            grep -iE 'upload|file|download|media|attachment' \"$RD/urls/all.txt\" | sort -u > \"$RD/urls/file_uploads.txt\" || true\n"
    "            grep -iE '\\.(env|bak|backup|old|sql|log|config|cfg|yml|yaml|pem|key|git|htaccess|zip|tar|gz|dump)(\\?|#|$)' \"$RD/urls/all.txt\" | sort -u > \"$RD/urls/sensitive_files.txt\" || true\n"
    "            grep -E '=' \"$RD/urls/all.txt\" | sort -u > \"$RD/urls/params.txt\" || true\n"
    '            for f in js_urls api_urls login_flows admin_panels file_uploads sensitive_files params; do\n'
    '              [ -f "$RD/urls/${f}.txt" ] && [ ! -s "$RD/urls/${f}.txt" ] && rm -f "$RD/urls/${f}.txt" || true\n'
    '            done\n'
    '            echo "📁 Classified: js=$(wc -l < "$RD/urls/js_urls.txt" 2>/dev/null || echo 0) api=$(wc -l < "$RD/urls/api_urls.txt" 2>/dev/null || echo 0) admin=$(wc -l < "$RD/urls/admin_panels.txt" 2>/dev/null || echo 0) login=$(wc -l < "$RD/urls/login_flows.txt" 2>/dev/null || echo 0) sensitive=$(wc -l < "$RD/urls/sensitive_files.txt" 2>/dev/null || echo 0) params=$(wc -l < "$RD/urls/params.txt" 2>/dev/null || echo 0)"\n'
    '          fi'
)
if juicy_echo in c and "📁 Classified:" not in c:
    must_replace(juicy_echo, classify, "URL classification")
elif "📁 Classified:" in c:
    print("SKIP: classification exists")
else:
    print("WARN: juicy marker missing")

yaml.safe_load(c)
p.write_text(c)
print("DONE lines", len(c.splitlines()))
