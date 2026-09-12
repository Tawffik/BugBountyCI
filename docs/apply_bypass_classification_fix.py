#!/usr/bin/env python3
"""Fix #4: Origin/Path bypass classification — weak signals are leads, not Confirmed."""
from pathlib import Path

p = Path(".github/workflows/zero-track-hunter.yml")
text = p.read_text()
assert "PLACEHOLDER" not in text and "Final all.txt" in text and "gospider" in text

if (
    "origin-ip-responds-redirect-only" in text
    and "PATH-BYPASS-LEAD" in text
    and 'leads.append(("Origin IP signal (not confirmed bypass)"' in text
):
    print("already applied")
    raise SystemExit(0)

old_origin = (
    '              if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 400 ] 2>/dev/null'
    '                  && [ "$test_len" -gt 200 ] && [ "$base_len" -gt 0 ]'
    '                  && [ "$size_diff" -lt $((base_len / 3 + 1)) ] && [ "$is_block_page" -eq 0 ]; then\n'
    '                echo "[ORIGIN-BYPASS-CONFIRMED] ${scheme}://${ip}/ (Host: ${{ env.TARGET }}) | status=${status} | body_len=${test_len} vs baseline=${base_len}" >> "$RD/waf_bypass/origin_bypass.txt"\n'
    '              elif [ "$status" != "000" ] && [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 400 ] 2>/dev/null && [ "$is_block_page" -eq 0 ]; then\n'
    '                echo "[origin-reachable-but-content-differs] ${scheme}://${ip}/ (Host: ${{ env.TARGET }}) | status=${status} | body_len=${test_len} vs baseline=${base_len}" >> "$RD/waf_bypass/origin_bypass.txt"\n'
    '              fi'
)

new_origin = '''              # CONFIRMED = real site content via origin IP (2xx only, not redirects).
              # content-differs = lead only (triage must NOT promote to Confirmed).
              # bare 3xx / empty body = IP responds but not a WAF-bypass finding.
              if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null \\
                  && [ "$test_len" -gt 200 ] && [ "$base_len" -gt 0 ] \\
                  && [ "$size_diff" -lt $((base_len / 3 + 1)) ] && [ "$is_block_page" -eq 0 ]; then
                echo "[ORIGIN-BYPASS-CONFIRMED] ${scheme}://${ip}/ (Host: ${{ env.TARGET }}) | status=${status} | body_len=${test_len} vs baseline=${base_len}" >> "$RD/waf_bypass/origin_bypass.txt"
              elif [ "$status" != "000" ] && [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null \\
                  && [ "$is_block_page" -eq 0 ] && [ "$test_len" -gt 50 ]; then
                echo "[origin-reachable-but-content-differs] ${scheme}://${ip}/ (Host: ${{ env.TARGET }}) | status=${status} | body_len=${test_len} vs baseline=${base_len}" >> "$RD/waf_bypass/origin_bypass.txt"
              elif [ "$status" != "000" ] && [ "$status" -ge 300 ] 2>/dev/null && [ "$status" -lt 400 ] 2>/dev/null; then
                echo "[origin-ip-responds-redirect-only] ${scheme}://${ip}/ (Host: ${{ env.TARGET }}) | status=${status} | body_len=${test_len} (not a confirmed bypass)" >> "$RD/waf_bypass/origin_bypass.txt"
              fi'''

if old_origin not in text:
    raise SystemExit("origin decision block not found")
text = text.replace(old_origin, new_origin, 1)
print("origin detection OK")

old_path = (
    '          : > "$RD/waf_bypass/path_bypass.txt"\n'
    '          while IFS= read -r host; do\n'
    '            host="$(echo "$host" | tr -d \'\\r\' | xargs)"; [ -z "$host" ] && continue\n'
    '            for test_path in "/%252e%252e%252f" "/%c0%af" "/ADMIN" "/./" "/;foo=bar"; do\n'
    '              s=$(proxychains4 -q curl -sk -o /dev/null -w "%{http_code}" --max-time 5 -H "User-Agent: $SCAN_USER_AGENT" "${host}${test_path}" 2>/dev/null || echo "000")\n'
    '              s="${s: -3}"\n'
    '              if [ "$s" = "200" ] || [ "$s" = "301" ] || [ "$s" = "302" ]; then\n'
    '                echo "[PATH-BYPASS] ${host}${test_path} | status=${s}" >> "$RD/waf_bypass/path_bypass.txt"\n'
    '                break\n'
    '              fi\n'
    '            done\n'
    '          done < "$INPUT"'
)

new_path = '''          : > "$RD/waf_bypass/path_bypass.txt"
          while IFS= read -r host; do
            host="$(echo "$host" | tr -d '\r' | xargs)"; [ -z "$host" ] && continue
            base_s=$(proxychains4 -q curl -sk -o /tmp/path_base_body -w "%{http_code}" --max-time 5 -H "User-Agent: $SCAN_USER_AGENT" "${host}/" 2>/dev/null || echo "000")
            base_s="${base_s: -3}"
            base_hash=$(md5sum /tmp/path_base_body 2>/dev/null | awk '{print $1}')
            for test_path in "/%252e%252e%252f" "/%c0%af" "/ADMIN" "/./" "/;foo=bar"; do
              s=$(proxychains4 -q curl -sk -o /tmp/path_test_body -w "%{http_code}" --max-time 5 -H "User-Agent: $SCAN_USER_AGENT" "${host}${test_path}" 2>/dev/null || echo "000")
              s="${s: -3}"
              [ "$s" = "000" ] && continue
              test_hash=$(md5sum /tmp/path_test_body 2>/dev/null | awk '{print $1}')
              if [ "$s" -ge 200 ] 2>/dev/null && [ "$s" -lt 300 ] 2>/dev/null; then
                if [ "$base_s" = "403" ] || [ "$base_s" = "401" ] || [ "$base_s" = "429" ] || [ "$base_s" = "000" ]; then
                  echo "[PATH-BYPASS] ${host}${test_path} | status=${s} baseline=${base_s} (unblocked vs blocked baseline)" >> "$RD/waf_bypass/path_bypass.txt"
                  break
                elif [ -n "$test_hash" ] && [ -n "$base_hash" ] && [ "$test_hash" != "$base_hash" ]; then
                  echo "[PATH-BYPASS-LEAD] ${host}${test_path} | status=${s} baseline=${base_s} (2xx body differs from /)" >> "$RD/waf_bypass/path_bypass.txt"
                  break
                fi
              fi
            done
          done < "$INPUT"'''

if old_path not in text:
    raise SystemExit("path bypass block not found")
text = text.replace(old_path, new_path, 1)
print("path detection OK")

old_triage = '''          for l in rl("waf_bypass/origin_bypass.txt"):
              # Direct-origin access is a stronger finding than a header trick -
              # it means the WAF/CDN can be skipped entirely, not just tricked
              # into thinking a request came from a trusted source.
              sev = "critical" if l.startswith("[ORIGIN-BYPASS-CONFIRMED]") else "medium"
              confirmed.append((SEV_RANK[sev], sev, "WAF Bypass (direct origin IP)", l))
          for l in rl("waf_bypass/ip_spoof_bypass.txt"):
              confirmed.append((SEV_RANK["high"], "high", "Access Control Bypass (spoofed IP header)", l))'''

new_triage = '''          for l in rl("waf_bypass/origin_bypass.txt"):
              if l.startswith("[ORIGIN-BYPASS-CONFIRMED]"):
                  confirmed.append((SEV_RANK["critical"], "critical", "WAF Bypass (direct origin IP)", l))
              elif l.startswith("[origin-reachable-but-content-differs]") or l.startswith("[origin-ip-responds-redirect-only]"):
                  leads.append(("Origin IP signal (not confirmed bypass)", l))
          for l in rl("waf_bypass/path_bypass.txt"):
              if l.startswith("[PATH-BYPASS]"):
                  confirmed.append((SEV_RANK["medium"], "medium", "Path encoding WAF bypass", l))
              elif l.startswith("[PATH-BYPASS-LEAD]"):
                  leads.append(("Path encoding lead (verify manually)", l))
          for l in rl("waf_bypass/ip_spoof_bypass.txt"):
              confirmed.append((SEV_RANK["high"], "high", "Access Control Bypass (spoofed IP header)", l))'''

if old_triage not in text:
    raise SystemExit("triage origin block not found")

old_init = "confirmed = []  # (severity_rank, severity_label, category, detail)"
new_init = "confirmed = []  # (severity_rank, severity_label, category, detail)\n          leads = []  # recon leads — NOT confirmed findings"
if "leads = []  # recon leads" not in text:
    if old_init not in text:
        raise SystemExit("confirmed init not found")
    text = text.replace(old_init, new_init, 1)
    text = text.replace("\n          leads = []\n          if confirmed:", "\n          if confirmed:", 1)
    print("moved leads init earlier")

text = text.replace(old_triage, new_triage, 1)
print("triage OK")

assert "Final all.txt" in text and "gospider" in text
p.write_text(text)
print("OK", len(text.splitlines()))
