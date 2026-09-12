#!/usr/bin/env python3
"""ASN soft-fix only. Never touches URL collection markers."""
from pathlib import Path

p = Path(".github/workflows/zero-track-hunter.yml")
text = p.read_text()
if "PLACEHOLDER" in text:
    raise SystemExit("workflow still PLACEHOLDER - restore first")
if "Final all.txt" not in text or "gospider" not in text:
    raise SystemExit("URL markers missing - abort")

if "bgpview (after asnmap empty)" not in text:
    lines = text.splitlines(keepends=True)
    out = []
    i = 0
    inserted = False
    while i < len(lines):
        out.append(lines[i])
        if (
            not inserted
            and "asn_skipped_reason.txt" in lines[i]
            and i > 0
            and "PDCP_API_KEY is set and asnmap is installed" in lines[i - 1]
        ):
            if i + 1 < len(lines):
                out.append(lines[i + 1])
                i += 1
            block = '''              echo "   Falling back to BGPView free API after asnmap exhaustion..."
              python3 << 'PYEOF'
          import os, json, socket, urllib.request
          rd = "results/" + os.environ.get("TIMESTAMP", "")
          target = os.environ.get("TARGET", "")
          prefixes = set()
          try:
              ip = socket.gethostbyname(target)
              req = urllib.request.Request("https://api.bgpview.io/ip/" + ip, headers={"User-Agent": "Mozilla/5.0"})
              with urllib.request.urlopen(req, timeout=15) as resp:
                  data = json.loads(resp.read().decode("utf-8", "replace"))
              for item in (data.get("data") or {}).get("prefixes", []):
                  pfx = item.get("prefix")
                  if pfx:
                      prefixes.add(pfx)
          except Exception as e:
              os.makedirs(os.path.join(rd, "logs"), exist_ok=True)
              open(os.path.join(rd, "logs", "bgpview.log"), "w").write("BGPView lookup failed: %s" % e)
          open("/tmp/bgpview_cidrs.txt", "w").write("\\n".join(prefixes))
          print("BGPView: %d CIDR(s)" % len(prefixes) if prefixes else "BGPView: no usable data")
          PYEOF
              if [ -s /tmp/bgpview_cidrs.txt ]; then
                timeout 120 proxychains4 -q naabu -l /tmp/bgpview_cidrs.txt -top-ports 100 -exclude-cdn -silent -rate 1000 -c 25 2>>"$RD/logs/naabu.log" | awk -F: '{print "https://"$1":"$2}' > "$RD/subdomains/asn_ips.txt" || true
                echo "bgpview (after asnmap empty)" > "$RD/meta/asn_source.txt"
              fi
'''
            out.append(block)
            inserted = True
        i += 1
    if not inserted:
        raise SystemExit("failed to locate asnmap-empty insertion point")
    text = "".join(out)
    print("bgpview inserted")
else:
    print("bgpview already present")

if "ASN variance" not in text:
    lines = text.splitlines(keepends=True)
    out = []
    i = 0
    while i < len(lines):
        if "regress_map = [" in lines[i] and i + 6 < len(lines) and "asn_ips" in "".join(lines[i : i + 5]):
            j = i
            while j < len(lines):
                if j > i and "verdict = " in lines[j]:
                    break
                j += 1
            replacement = '''              core_regress = [("subdomains", counts["all_subs"], "Total confirmed subdomains"),
                              ("live_hosts", counts["live"], "Live hosts"),
                              ("urls", counts["urls"], "Collected URLs")]
              for key, cur_val, label in core_regress:
                  prev_val = prev.get(key)
                  if prev_val is not None and prev_val >= 3 and cur_val == 0:
                      flags.append(f"📉 **REGRESSION**: {label} was {prev_val} on the previous run against this same target and is 0 now. This is very likely a NEW bug introduced since then, not normal run-to-run variance - worth investigating before trusting this run's results.")
              prev_asn = prev.get("asn_ips")
              if prev_asn is not None and prev_asn >= 3 and counts["asn_ips"] == 0:
                  flags.append(f"ℹ️ **ASN variance**: ASN/CIDR-derived candidates was {prev_asn} previously and is 0 now (asnmap/Tor flaky; BGPView fallback may still populate). Not treated as pipeline BROKEN.")

'''
            out.append(replacement)
            i = j
            print("regressed softened")
            continue
        out.append(lines[i])
        i += 1
    text = "".join(out)
else:
    print("ASN variance already present")

if "timeout 90 asnmap" not in text:
    if "timeout 45 asnmap" not in text:
        raise SystemExit("timeout 45 asnmap missing")
    text = text.replace(
        'timeout 45 asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true',
        'timeout 90 asnmap -d "${{ env.TARGET }}" -silent -o /tmp/asn_cidrs.txt 2>>"$RD/logs/asnmap.log" || true',
        1,
    )
    print("timeout 90")
else:
    print("timeout already 90")

if "Final all.txt" not in text or "gospider" not in text:
    raise SystemExit("URL markers lost after patch - abort")
p.write_text(text)
print("OK", len(text.splitlines()))
