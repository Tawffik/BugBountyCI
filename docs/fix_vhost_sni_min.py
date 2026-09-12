#!/usr/bin/env python3
from pathlib import Path
p = Path(".github/workflows/zero-track-hunter.yml")
t = p.read_text()
assert "Final all.txt" in t
if "VHOST_SNI_RESOLVE_2026_09" in t:
    print("already"); raise SystemExit(0)

old_echo = 'echo "\U0001f50d Virtual host discovery on shared IPs..."'
# fallback without relying on emoji escape - search by unique ASCII
if "Virtual host discovery on shared IPs..." not in t:
    raise SystemExit("echo missing")
t = t.replace(
    'echo "\U0001f50d Virtual host discovery on shared IPs..."',
    'echo "\U0001f50d Virtual host discovery on shared IPs (Host + SNI via --resolve)..."\n          # VHOST_SNI_RESOLVE_2026_09',
    1,
)
if "VHOST_SNI_RESOLVE_2026_09" not in t:
    t = t.replace(
        "Virtual host discovery on shared IPs...",
        "Virtual host discovery on shared IPs (Host + SNI via --resolve)...",
        1,
    )
    # insert marker after the echo line containing VHost
    idx = t.find("Virtual host discovery on shared IPs (Host + SNI via --resolve)")
    line_end = t.find("\n", idx)
    t = t[:line_end] + "\n          # VHOST_SNI_RESOLVE_2026_09" + t[line_end:]

old_base = '''base_status=$(proxychains4 -q curl -sk --max-time 6 -H "Host: nonexistent-$RANDOM.$TARGET" -H "User-Agent: $SCAN_USER_AGENT" -o /tmp/vhost_base -w "%{http_code}" "https://$ip/" 2>/dev/null || echo "000")
              base_status="${base_status: -3}"  # curl -w already prints 000 on failure AND exits non-zero, so the || echo "000" fallback doubles it to 000000 - truncate to be safe either way
              blen=$(wc -c < /tmp/vhost_base 2>/dev/null || echo 0)
              for vh in dev staging admin internal test api-internal vpn preprod uat qa; do
                : > /tmp/vhost_test
                test_status=$(proxychains4 -q curl -sk --max-time 6 -H "Host: ${vh}.${TARGET}" -H "User-Agent: $SCAN_USER_AGENT" -o /tmp/vhost_test -w "%{http_code}" "https://$ip/" 2>/dev/null || echo "000")
                test_status="${test_status: -3}"  # curl -w already prints 000 on failure AND exits non-zero, so the || echo "000" fallback doubles it to 000000 - truncate to be safe either way
                tlen=$(wc -c < /tmp/vhost_test 2>/dev/null || echo 0)
                diff=$(( tlen > blen ? tlen - blen : blen - tlen ))
                # Previously the captured status codes (base_status/test_status) were
                # thrown away and only byte-length was compared - so a vhost returning
                # the SAME length but a DIFFERENT status (e.g. 200 vs 403, a very common
                # "this vhost exists but you're not authorized" signal) was silently
                # missed. Flag on either signal now.
                if { [ "$blen" -gt 0 ] && [ "$diff" -gt 50 ]; } || [ "$test_status" != "$base_status" ]; then
                  echo "${vh}.${TARGET} on ${ip} (status ${base_status}->${test_status}, body differs by ${diff} bytes)" >> "$RD/live/vhosts.txt"
                fi
              done'''

new_base = '''# skip non-IPv4
              echo "$ip" | grep -qE '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' || continue
              fake="nonexistent-$RANDOM.$TARGET"
              base_status=$(proxychains4 -q curl -sk --max-time 8 --resolve "${fake}:443:${ip}" -H "Host: ${fake}" -H "User-Agent: $SCAN_USER_AGENT" -o /tmp/vhost_base -w "%{http_code}" "https://${fake}/" 2>/dev/null || echo "000")
              base_status="${base_status: -3}"
              if [ "$base_status" = "000" ]; then
                base_status=$(curl -sk --max-time 8 --resolve "${fake}:443:${ip}" -H "Host: ${fake}" -H "User-Agent: $SCAN_USER_AGENT" -o /tmp/vhost_base -w "%{http_code}" "https://${fake}/" 2>/dev/null || echo "000")
                base_status="${base_status: -3}"
                vhost_curl="curl -sk"
              else
                vhost_curl="proxychains4 -q curl -sk"
              fi
              blen=$(wc -c < /tmp/vhost_base 2>/dev/null || echo 0)
              for vh in dev staging admin internal test api-internal vpn preprod uat qa portal beta dashboard; do
                name="${vh}.${TARGET}"
                : > /tmp/vhost_test
                test_status=$($vhost_curl --max-time 8 --resolve "${name}:443:${ip}" -H "Host: ${name}" -H "User-Agent: $SCAN_USER_AGENT" -o /tmp/vhost_test -w "%{http_code}" "https://${name}/" 2>/dev/null || echo "000")
                test_status="${test_status: -3}"
                tlen=$(wc -c < /tmp/vhost_test 2>/dev/null || echo 0)
                diff=$(( tlen > blen ? tlen - blen : blen - tlen ))
                if [ "$base_status" = "000" ] && [ "$test_status" = "000" ]; then continue; fi
                if { [ "$blen" -gt 0 ] && [ "$diff" -gt 50 ]; } || { [ "$test_status" != "$base_status" ] && [ "$test_status" != "000" ]; }; then
                  echo "${name} on ${ip} (SNI+Host, status ${base_status}->${test_status}, body differs by ${diff} bytes)" >> "$RD/live/vhosts.txt"
                fi
              done'''

if old_base not in t:
    raise SystemExit("base block missing")
t = t.replace(old_base, new_base, 1)
assert "Final all.txt" in t and "VHOST_SNI_RESOLVE_2026_09" in t
p.write_text(t)
print("OK", len(t.splitlines()))
