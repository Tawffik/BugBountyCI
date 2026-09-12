#!/usr/bin/env python3
from pathlib import Path
p = Path(".github/workflows/zero-track-hunter.yml")
t = p.read_text()
assert "Final all.txt" in t and "PLACEHOLDER" not in t
if "live classification:" in t and "live/verified.txt" in t:
    print("already")
    raise SystemExit(0)

idx = t.find("Live hosts:")
if idx < 0:
    raise SystemExit("Live hosts line missing")
lc = t.find("live_count=", idx)
if lc < 0 or lc - idx > 400:
    raise SystemExit("live_count line missing")
lc_start = t.rfind("\n", 0, lc) + 1

block = r"""          # Classify verified vs unverified for operators + downstream caps
          : > "$RD/live/verified.txt"
          : > "$RD/live/unverified.txt"
          probe_path=$(cat "$RD/meta/live_probe_path.txt" 2>/dev/null || echo "unknown")
          case "$probe_path" in
            dns-seed|ports-enriched|apex-seed)
              cp "$RD/live/live.txt" "$RD/live/unverified.txt" 2>/dev/null || true
              echo "ℹ️ live classification: $(wc -l < "$RD/live/unverified.txt" 2>/dev/null || echo 0) UNVERIFIED ($probe_path)"
              ;;
            *)
              if [ -s "$RD/live/live.txt" ]; then
                cp "$RD/live/live.txt" "$RD/live/verified.txt" 2>/dev/null || true
                echo "ℹ️ live classification: $(wc -l < "$RD/live/verified.txt" 2>/dev/null || echo 0) VERIFIED ($probe_path)"
              fi
              ;;
          esac
"""
t = t[:lc_start] + block + t[lc_start:]

old_cmd = 'proxychains4 -q arjun -u "$host" -t 10 --rate-limit 20 -oT /tmp/arjun_out.txt 2>>"$RD/logs/arjun.log" >/dev/null || true'
new_cmd = 'proxychains4 -q arjun -u "$host" -t 10 --rate-limit 20 "${AUTH_ARGS[@]}" -oT /tmp/arjun_out.txt 2>>"$RD/logs/arjun.log" >/dev/null || true'
if old_cmd not in t:
    raise SystemExit("arjun cmd missing")
t = t.replace(old_cmd, new_cmd, 1)
t = t.replace(
    'AUTH_ARGS+=(-C "${{ env.AUTH_COOKIE }}")',
    'AUTH_ARGS+=(--headers "Cookie: ${{ env.AUTH_COOKIE }}")',
    1,
)
assert "Final all.txt" in t and "live/verified.txt" in t
p.write_text(t)
print("OK", len(t.splitlines()))
