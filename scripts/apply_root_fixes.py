#!/usr/bin/env python3
"""Safe pipeline patches from superdrug runs #7/#13/#14 root causes."""
from pathlib import Path
import yaml

p = Path(".github/workflows/zero-track-hunter.yml")
c = p.read_text()

def soft_replace(old, new, label, count=1):
    global c
    if old not in c:
        print("SKIP:", label)
        return False
    c = c.replace(old, new, count)
    print("OK:", label)
    return True

# 1) uro
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
if needle in c:
    soft_replace(needle, replacement, "uro safety")
elif "uro empty" in c:
    print("SKIP: uro already patched")
else:
    raise SystemExit("ABORT: uro pattern missing")

# 2) merge
soft_replace(
    'cat "$RD"/urls/*.txt 2>/dev/null | sort -u > /tmp/urls_merged.txt',
    ': > /tmp/urls_merged.txt\n'
    '          for src in wayback wayback_js gau katana hakrawler urlscan otx html_extract robots_sitemap; do\n'
    '            f="$RD/urls/${src}.txt"\n'
    '            [ -s "$f" ] && cat "$f" >> /tmp/urls_merged.txt\n'
    '          done\n'
    '          sort -u -o /tmp/urls_merged.txt /tmp/urls_merged.txt 2>/dev/null || true',
    "merge sources",
)

# 3) asnmap
soft_replace(
    'timeout 60 proxychains4 -q asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true',
    'timeout 45 asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true\n'
    '            if [ ! -s /tmp/asn_cidrs.txt ]; then\n'
    '              echo "⚠️ asnmap DIRECT empty — trying Tor..."\n'
    '              timeout 60 proxychains4 -q asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true\n'
    '            fi',
    "asnmap DIRECT",
)

# 4) classify
juicy = '          echo "✅ Juicy URLs (params/admin/api/config): $(wc -l < "$RD/urls/juicy.txt" 2>/dev/null || echo 0)"'
if juicy in c and "📁 Classified:" not in c:
    soft_replace(
        juicy,
        juicy + '\n\n'
        '          # Methodology classification (grep-only)\n'
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
        '          fi',
        "URL classification",
    )
else:
    print("SKIP: classification")

# 5) cariddi
old_c = (
    "timeout 180 proxychains4 -q bash -c \"cat '$CARIDDI_LIST' | cariddi -e -s -info -err -plain -ua '$SCAN_USER_AGENT' -t 10\""
    "               > \"$RD/js_deep/cariddi_findings.txt\" 2>>\"$RD/logs/cariddi.log\" || true"
)
new_c = (
    'timeout 180 proxychains4 -q bash -c "cat \'$CARIDDI_LIST\' | cariddi -e -s -info -err -ua \'$SCAN_USER_AGENT\' -t 10 -ot /tmp/cariddi_out" '
    '2>>"$RD/logs/cariddi.log" || true\n'
    '            : > "$RD/js_deep/cariddi_findings.txt"\n'
    '            cat /tmp/cariddi_out.txt /tmp/cariddi_out.*.txt 2>/dev/null >> "$RD/js_deep/cariddi_findings.txt" || true\n'
    '            if [ ! -s "$RD/js_deep/cariddi_findings.txt" ]; then\n'
    '              timeout 120 proxychains4 -q bash -c "cat \'$CARIDDI_LIST\' | cariddi -e -s -ua \'$SCAN_USER_AGENT\' -t 8" '
    '                > /tmp/cariddi_stdout.txt 2>>"$RD/logs/cariddi.log" || true\n'
    '              grep -viE "plain mode|you should define|Examples:|cariddi -" /tmp/cariddi_stdout.txt '
    '>> "$RD/js_deep/cariddi_findings.txt" 2>/dev/null || true\n'
    '            fi\n'
    '            grep -viE "plain mode|you should define|Examples:" "$RD/js_deep/cariddi_findings.txt" '
    '| grep -v "^$" > /tmp/cariddi_clean.txt 2>/dev/null || true\n'
    '            if [ -s /tmp/cariddi_clean.txt ]; then cp /tmp/cariddi_clean.txt "$RD/js_deep/cariddi_findings.txt"; fi'
)
soft_replace(old_c, new_c, "cariddi -ot + help filter")

# 6) nuclei cap 25 -> 8
old_n = (
    "                if [ -s \"$RD/live/interesting_ranked.txt\" ]; then\n"
    "                  awk '{print $2}' \"$RD/live/interesting_ranked.txt\" | head -25 > /tmp/nuclei_capped.txt\n"
    "                  INPUT=/tmp/nuclei_capped.txt\n"
    "                  echo \"⚠️ Unverified live ($probe_path) - Nuclei capped to top 25 ranked hosts\"\n"
    "                fi"
)
new_n = (
    "                if [ -s \"$RD/live/interesting_ranked.txt\" ]; then\n"
    "                  awk '{print $2}' \"$RD/live/interesting_ranked.txt\" | head -8 > /tmp/nuclei_capped.txt\n"
    "                  INPUT=/tmp/nuclei_capped.txt\n"
    "                  echo \"⚠️ Unverified live ($probe_path) - Nuclei capped to top 8 ranked hosts (Tor/WAF error budget)\"\n"
    "                elif [ -s \"$RD/live/expensive_targets.txt\" ]; then\n"
    "                  head -8 \"$RD/live/expensive_targets.txt\" > /tmp/nuclei_capped.txt\n"
    "                  INPUT=/tmp/nuclei_capped.txt\n"
    "                  echo \"⚠️ Unverified live ($probe_path) - Nuclei capped to top 8 expensive_targets\"\n"
    "                fi"
)
soft_replace(old_n, new_n, "nuclei top-8 cap")

yaml.safe_load(c)
p.write_text(c)
print("DONE lines", len(c.splitlines()))
