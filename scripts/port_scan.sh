#!/usr/bin/env bash
# Port Scanning stage for Zero Track (extracted from workflow to stay under
# GitHub Actions max expression length for `run:` blocks).
set -uo pipefail
RD="results/${TIMESTAMP}"
TARGET="${TARGET:?TARGET required}"
SCAN_USER_AGENT="${SCAN_USER_AGENT:-Mozilla/5.0}"

RD="results/${TIMESTAMP}"
# Prefer DNS-confirmed hosts when available (live probe set).
# all_subs may include unresolved names; naabu via Tor often fails DNS
# with FTL "no valid ipv4 or ipv6 targets" (superdrug #101, capital #100).
if [ -s "$RD/subdomains/resolved.txt" ]; then
  INPUT="$RD/subdomains/resolved.txt"
else
  INPUT="$RD/subdomains/all_subs.txt"
fi
[ -s "$INPUT" ] || { echo "${TARGET}" > /tmp/fallback.txt; INPUT=/tmp/fallback.txt; }
# Everything so far only ever checked 80/443. Admin panels, dev/staging
# services, and internal tools are very commonly left open on non-standard
# ports that nothing above would ever touch - naabu finds those.
# Ensure ports.txt always exists — bash `wc -l < missing` under
# set -e/pipefail exits 2 (seen on sengi capital.com run 35925487689)
# even with `2>/dev/null || echo 0` inside $(...).
: > "$RD/live/ports.txt"
if command -v naabu >/dev/null; then
  # top-ports 100 + explicit high-value ports (admin panels, DBs, remote access,
  # containers, CI) that sometimes sit outside the generic top-100 ranking
  HIGH_VALUE_PORTS="81,3000,3001,4000,4040,4443,5000,5432,5601,5900,6379,7001,8000,8080,8081,8443,8888,9000,9090,9200,9418,10443,27017"
  # BUGFIX (2026-09-16): this naabu call had no timeout wrapper at
  # all - bounded only by the whole step's timeout-minutes.
  # Confirmed on binance.com (4,362 subdomains, scanning ~113
  # ports each through Tor): it silently consumed the entire step
  # budget, leaving zero time for the ranking/critical-seeds tail
  # below - which is exactly why expensive_targets.txt,
  # scan_order.txt and critical_seeds_note.txt all ended up
  # missing on that run, starving Nuclei/Arjun/Corsy of their
  # prioritized target lists (Nuclei fell back to scanning just 8
  # hosts out of 8,728 live ones). Capping naabu itself guarantees
  # the rest of this step always gets a real chance to run.
  # Prefer non-sudo on runners where passwordless sudo is flaky; fall back to sudo.
  NAABU_BIN="$(command -v naabu)"
  # BUGFIX 2026-10-01: Tor-only hostname scan -> FTL no valid ipv4/ipv6
  # on multiple runs while live hosts existed. DIRECT first (ASN path pattern).
  # BUGFIX 2026-10-02: classification must not use shared logs/naabu.log
  # (ASN path also appends there) and must preserve exit codes — timeout/FTL
  # with ports=0 is ERROR, not EMPTY. Dedicated naabu_portscan.log segment.
  PORT_SCAN_STATUS="NOT_RUN"
  DIRECT_RC=0
  TOR_RC=0
  mkdir -p "$RD/logs"
  : > "$RD/logs/naabu_portscan.log"
  # Build literal IPv4 targets for naabu.
  # #104 evidence (nuva.finance): dnsx -l -a -resp-only returned EMPTY while
  # resolved.txt had 6 live hostnames and httpx saw ~19 hosts (incl. IPs).
  # naabu then FTL "no valid ipv4 or ipv6 targets" on hostnames under DIRECT.
  # Prefer dig/getent + IPs already observed in live.txt (port scan runs after live).
  : > /tmp/port_scan_ips.txt
  # 1) IPs already present in live surface (ASN probe / httpx IP URLs)
  if [ -s "$RD/live/live.txt" ]; then
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$RD/live/live.txt" 2>/dev/null                 | grep -vE '^(0\.|127\.|10\.|192\.168\.|169\.254\.)'                 | sort -u >> /tmp/port_scan_ips.txt || true
  fi
  if [ -s "$RD/subdomains/asn_ips.txt" ]; then
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$RD/subdomains/asn_ips.txt" 2>/dev/null                 | sort -u >> /tmp/port_scan_ips.txt || true
  fi
  # 2) dig/getent for each hostname in INPUT (do not rely on dnsx -l alone)
  while IFS= read -r h || [ -n "$h" ]; do
    h="$(echo "$h" | tr -d '\r' | xargs)"
    [ -z "$h" ] && continue
    # already an IP?
    if echo "$h" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
      echo "$h" >> /tmp/port_scan_ips.txt
      continue
    fi
    if command -v dig >/dev/null 2>&1; then
      dig +short +time=2 +tries=1 A "$h" 2>/dev/null | grep -E '^[0-9.]+$' | head -3 >> /tmp/port_scan_ips.txt || true
    fi
    if command -v getent >/dev/null 2>&1; then
      getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9.]+$' | head -2 >> /tmp/port_scan_ips.txt || true
    fi
  done < "$INPUT"
  # 3) optional dnsx via stdin (stdin path matches DNS resolve stage; -l had hang history)
  if command -v dnsx >/dev/null 2>&1 && [ -s "$INPUT" ]; then
    timeout 90 bash -c 'cat "$0" | dnsx -silent -a -resp-only -t 30 -retry 1' "$INPUT"                 2>>"$RD/logs/naabu_portscan.log" | grep -E '^[0-9.]+$' >> /tmp/port_scan_ips.txt || true
  fi
  if [ -s /tmp/port_scan_ips.txt ]; then
    sort -u /tmp/port_scan_ips.txt -o /tmp/port_scan_ips.txt
    # drop obvious non-routable noise
    grep -vE '^(0\.|127\.|10\.|192\.168\.|169\.254\.|255\.)' /tmp/port_scan_ips.txt                 | sort -u -o /tmp/port_scan_ips.txt || true
  fi
  PORT_INPUT="$INPUT"
  if [ -s /tmp/port_scan_ips.txt ]; then
    PORT_INPUT=/tmp/port_scan_ips.txt
    echo "Port scan IP targets: $(wc -l < "$PORT_INPUT" | tr -d ' ') IPs (from dig/getent/live/dnsx; host source=$INPUT lines=$(wc -l < "$INPUT" | tr -d ' '))"
    cp /tmp/port_scan_ips.txt "$RD/logs/port_scan_ips.txt" 2>/dev/null || true
  else
    echo "Port scan IP resolution empty — using hostnames as last resort (naabu may FTL)"
  fi
  echo "Port scan input: $PORT_INPUT ($(wc -l < "$PORT_INPUT" | tr -d ' ') targets) (source=$INPUT)"
  set +e
  timeout 480 "$NAABU_BIN" -l "$PORT_INPUT" -top-ports 100 -p "$HIGH_VALUE_PORTS" -exclude-cdn -silent -rate 800 -c 15 -o "$RD/live/ports.txt" 2>>"$RD/logs/naabu_portscan.log"
  DIRECT_RC=$?
  if [ "$DIRECT_RC" -ne 0 ]; then
    timeout 480 sudo -n "$NAABU_BIN" -l "$PORT_INPUT" -top-ports 100 -p "$HIGH_VALUE_PORTS" -exclude-cdn -silent -rate 800 -c 15 -o "$RD/live/ports.txt" 2>>"$RD/logs/naabu_portscan.log"
    DIRECT_RC=$?
  fi
  # If still zero and FTL/empty, one DIRECT pass without -exclude-cdn
  # (CDN filter can drop all targets on fully-CDN assets).
  port_n_tmp=$(wc -l < "$RD/live/ports.txt" 2>/dev/null | tr -d ' ' || echo 0)
  if [ "${port_n_tmp:-0}" -eq 0 ]; then
    echo "naabu DIRECT+cdn-exclude ports=0 — retry DIRECT without -exclude-cdn..."
    timeout 480 "$NAABU_BIN" -l "$PORT_INPUT" -top-ports 100 -p "$HIGH_VALUE_PORTS" -silent -rate 800 -c 15 -o "$RD/live/ports.txt" 2>>"$RD/logs/naabu_portscan.log"
    DIRECT_RC=$?
    if [ "$DIRECT_RC" -ne 0 ]; then
      timeout 480 sudo -n "$NAABU_BIN" -l "$PORT_INPUT" -top-ports 100 -p "$HIGH_VALUE_PORTS" -silent -rate 800 -c 15 -o "$RD/live/ports.txt" 2>>"$RD/logs/naabu_portscan.log"
      DIRECT_RC=$?
    fi
  fi
  set -e
  cat "$RD/logs/naabu_portscan.log" >> "$RD/logs/naabu.log" 2>/dev/null || true
  [ -f "$RD/live/ports.txt" ] || : > "$RD/live/ports.txt"
  port_n=$(wc -l < "$RD/live/ports.txt" 2>/dev/null | tr -d ' ' || echo 0)
  if [ "${port_n:-0}" -eq 0 ]; then
    echo "naabu DIRECT rc=$DIRECT_RC ports=0 — Tor fallback (lower rate)..."
    : > /tmp/naabu_tor_segment.log
    set +e
    timeout 480 proxychains4 -q "$NAABU_BIN" -l "${PORT_INPUT:-$INPUT}" -top-ports 100 -p "$HIGH_VALUE_PORTS" -silent -rate 200 -c 5 -o "$RD/live/ports.txt" 2>>/tmp/naabu_tor_segment.log
    TOR_RC=$?
    if [ "$TOR_RC" -ne 0 ]; then
      timeout 480 sudo -n proxychains4 -q "$NAABU_BIN" -l "${PORT_INPUT:-$INPUT}" -top-ports 100 -p "$HIGH_VALUE_PORTS" -silent -rate 200 -c 5 -o "$RD/live/ports.txt" 2>>/tmp/naabu_tor_segment.log
      TOR_RC=$?
    fi
    set -e
    cat /tmp/naabu_tor_segment.log >> "$RD/logs/naabu_portscan.log" 2>/dev/null || true
    cat /tmp/naabu_tor_segment.log >> "$RD/logs/naabu.log" 2>/dev/null || true
    [ -f "$RD/live/ports.txt" ] || : > "$RD/live/ports.txt"
    port_n=$(wc -l < "$RD/live/ports.txt" 2>/dev/null | tr -d ' ' || echo 0)
  fi
  # Connect-scan fallback when SYN/default still yields 0 (common without CAP_NET_RAW)
  if [ "${port_n:-0}" -eq 0 ] && [ -s "${PORT_INPUT:-$INPUT}" ]; then
    echo "naabu still ports=0 after DIRECT/Tor — try -scan-type connect..."
    set +e
    timeout 300 "$NAABU_BIN" -l "${PORT_INPUT:-$INPUT}" -top-ports 100 -p "$HIGH_VALUE_PORTS" -scan-type connect -silent -rate 400 -c 10 -o "$RD/live/ports.txt" 2>>"$RD/logs/naabu_portscan.log"
    CONNECT_RC=$?
    if [ "$(wc -l < "$RD/live/ports.txt" 2>/dev/null | tr -d ' ' || echo 0)" -eq 0 ]; then
      timeout 300 sudo -n "$NAABU_BIN" -l "${PORT_INPUT:-$INPUT}" -top-ports 100 -p "$HIGH_VALUE_PORTS" -scan-type connect -silent -rate 400 -c 10 -o "$RD/live/ports.txt" 2>>"$RD/logs/naabu_portscan.log"
      CONNECT_RC=$?
    fi
    set -e
    [ -f "$RD/live/ports.txt" ] || : > "$RD/live/ports.txt"
    port_n=$(wc -l < "$RD/live/ports.txt" 2>/dev/null | tr -d ' ' || echo 0)
    echo "naabu connect-scan rc=${CONNECT_RC:-?} ports=${port_n:-0}"
    if [ "${port_n:-0}" -eq 0 ] && [ "${CONNECT_RC:-1}" -ne 0 ]; then
      DIRECT_RC=${DIRECT_RC:-1}
    fi
    cat "$RD/logs/naabu_portscan.log" >> "$RD/logs/naabu.log" 2>/dev/null || true
  fi
  # Classification priority: ports>0 → OK; else exit/timeout/FTL → ERROR; else EMPTY
  # timeout(1) returns 124 on expiry.
  _ftl=0
  if grep -qE "FTL|Could not run enumeration|no valid ipv4|no valid ipv6" "$RD/logs/naabu_portscan.log" 2>/dev/null; then
    _ftl=1
  fi
  if [ "${port_n:-0}" -gt 0 ]; then
    PORT_SCAN_STATUS="OK"
  elif [ "$_ftl" -eq 1 ] || [ "${DIRECT_RC:-0}" -ne 0 ] || [ "${TOR_RC:-0}" -ne 0 ]; then
    PORT_SCAN_STATUS="ERROR"
    echo "::warning::Port scan ERROR — empty ports.txt is tool/network/timeout failure (direct_rc=$DIRECT_RC tor_rc=$TOR_RC ftl=$_ftl), not clean target"
  else
    PORT_SCAN_STATUS="EMPTY"
  fi
  echo "✅ Open host:port pairs: ${port_n:-0}"
  awk -F: '$2!=80 && $2!=443 {print}' "$RD/live/ports.txt" 2>/dev/null > /tmp/nonstd_ports.txt || true
  if [ -s /tmp/nonstd_ports.txt ]; then
    # BUGFIX: same broken "-l" bulk-mode pattern proven unreliable for the
    # main Live Host Probing step (confirmed on 3 real targets: httpx -l
    # deterministically wrote 0 bytes even when individual "-u" calls on
    # the exact same hosts/proxy worked fine) - replaced with the same
    # proven-working per-host loop used there.
    # BUGFIX 2026-09-08: same parallel JSON/text append corruption as
    # live-probe. Each probe writes its own temp file then we merge.
    # Concurrency 10 → 4 for Tor stability. Also extract clean host:port
    # URLs so later phases actually get usable targets.
    tmp_ns=$(mktemp -d)
    running=0; start_sec=$SECONDS; idx=0
    while IFS= read -r hp; do
      [ -z "$hp" ] && continue
      if [ $((SECONDS - start_sec)) -ge 90 ]; then break; fi
      idx=$((idx + 1))
      (
        proxychains4 -q httpx -u "$hp" -silent -status-code -title -follow-redirects                     -H "User-Agent: $SCAN_USER_AGENT" -timeout 8                     2>>"$RD/logs/httpx.log" > "$tmp_ns/$(printf '%05d' $idx).txt" || true
      ) &
      running=$((running + 1))
      if [ "$running" -ge 4 ]; then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
    done < /tmp/nonstd_ports.txt
    wait
    cat "$tmp_ns"/*.txt 2>/dev/null | grep -v '^\s*$' > "$RD/live/nonstandard_live.txt" || : > "$RD/live/nonstandard_live.txt"
    rm -rf "$tmp_ns"
    echo "✅ Live services on non-standard ports: $(wc -l < "$RD/live/nonstandard_live.txt" 2>/dev/null || echo 0)"
    # Merge host:port URLs into live.txt so nuclei/API/JS/fuzzing all see them
    # httpx output format is typically: https://host:port [status] [title]
    awk '{print $1}' "$RD/live/nonstandard_live.txt" 2>/dev/null | grep -E '^https?://' >> "$RD/live/live.txt" || true
    sort -u -o "$RD/live/live.txt" "$RD/live/live.txt"
  fi
else
  echo "⚠️ naabu not available, skipping port scan"
  PORT_SCAN_STATUS="NOT_RUN"
fi

# Truthful phase status: ERROR ≠ EMPTY (runs #100/#101 had empty ports + FTL)
mkdir -p "$RD/meta/phases"
_ps="${PORT_SCAN_STATUS:-UNKNOWN}"
_pd="ports=$(wc -l < "$RD/live/ports.txt" 2>/dev/null | tr -d ' ' || echo 0)"
if [ -f scripts/pipeline_lib.sh ]; then
  # shellcheck source=/dev/null
  . scripts/pipeline_lib.sh 2>/dev/null || true
fi
if declare -f write_phase_status >/dev/null 2>&1; then
  write_phase_status "$RD" "port_scan" "$_ps" "$_pd"
else
  printf '{"phase":"port_scan","status":"%s","detail":"%s"}\n' "$_ps" "$_pd" > "$RD/meta/phases/port_scan.json"
fi
echo "port_scan phase status=$_ps $_pd"

# Always enrich live.txt from naabu open ports (union, never shrink).
# Critical for cases where Tor/direct probe failed but DNS+ports succeeded
# (superdrug: 6 resolved subs with 80/443 open, live probe returned 0).
if [ -s "$RD/live/ports.txt" ]; then
  echo "🔗 Enriching live.txt from open ports..."
  : > /tmp/port_urls.txt
  while IFS= read -r hp; do
    [ -z "$hp" ] && continue
    host="${hp%%:*}"; port="${hp##*:}"
    [ -z "$host" ] || [ -z "$port" ] && continue
    if [ "$port" = "443" ] || [ "$port" = "8443" ] || [ "$port" = "9443" ]; then
      echo "https://${host}" >> /tmp/port_urls.txt
      [ "$port" != "443" ] && echo "https://${host}:${port}" >> /tmp/port_urls.txt
    elif [ "$port" = "80" ]; then
      echo "http://${host}" >> /tmp/port_urls.txt
      echo "https://${host}" >> /tmp/port_urls.txt
    else
      # non-standard: both schemes with explicit port
      echo "http://${host}:${port}" >> /tmp/port_urls.txt
      echo "https://${host}:${port}" >> /tmp/port_urls.txt
    fi
  done < "$RD/live/ports.txt"
  sort -u -o /tmp/port_urls.txt /tmp/port_urls.txt
  before=$(wc -l < "$RD/live/live.txt" 2>/dev/null || echo 0)
  cat /tmp/port_urls.txt >> "$RD/live/live.txt" 2>/dev/null || true
  sort -u -o "$RD/live/live.txt" "$RD/live/live.txt"
  after=$(wc -l < "$RD/live/live.txt" 2>/dev/null || echo 0)
  echo "✅ live.txt after port enrichment: $after (was $before)"
  # If we still have zero verified JSON but have candidates, keep path marker honest
  if [ ! -s "$RD/live/live.json" ] && [ -s "$RD/live/live.txt" ]; then
    echo "ports-enriched" > "$RD/meta/live_probe_path.txt"
  fi
fi

# --- Interesting-host prioritization (2026-09-08) ---
# Main domain alone rarely yields high-value findings. Rank live hosts
# so every downstream scanner (fuzzing, arjun, nuclei, API discovery)
# hits admin/api/staging/dev/internal first — where bugs actually live.
: > "$RD/live/interesting.txt"
: > "$RD/live/interesting_ranked.txt"
if [ -s "$RD/live/live.txt" ]; then
  # BUGFIX (2026-09-14): this while-loop does 8+ regex matches per
  # line in plain bash - fine for hundreds of hosts, but confirmed
  # on binance.com (tens of thousands of live.txt entries after
  # port-enrichment) to still be running when this step's
  # timeout-minutes killed it mid-way, before the critical-seeds
  # merge at the end of this step ever ran - which is how live.txt
  # ended up completely empty in that run despite port-enrichment
  # having already populated it. Capping the ranking pass bounds
  # this step's worst-case runtime regardless of target size;
  # scan_order.txt/expensive_targets.txt below still cover the
  # full live.txt via the union merges.
  RANK_INPUT="$RD/live/live.txt"
  rank_total=$(wc -l < "$RD/live/live.txt" 2>/dev/null || echo 0)
  if [ "${rank_total:-0}" -gt 5000 ]; then
    head -5000 "$RD/live/live.txt" > /tmp/rank_input.txt
    RANK_INPUT=/tmp/rank_input.txt
    echo "ℹ️ live.txt has $rank_total hosts - ranking pass capped to first 5000 to bound step runtime"
  fi
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    host=$(echo "$url" | sed -E 's#https?://##' | cut -d/ -f1 | cut -d: -f1)
    score=0
    # Match label prefixes (api-s1, api1, try-app) not only exact labels
    echo "$host" | grep -qiE '(^|\.)(admin|adm|administrator|portal|panel|console|dashboard|manage|manager|cms|cpanel|webmail|owa|exchange)([-.]|$)' && score=$((score+100))
    echo "$host" | grep -qiE '(^|\.)(api|graphql|gql|rest|gateway|backend|svc|service|ws|websocket)([-.]|$)|(^|\.|-)(api)([-.]|$)|-api\.|\.api\.' && score=$((score+90))
    echo "$host" | grep -qiE '(^|\.)(staging|stage|stg|dev|devel|development|test|qa|uat|preprod|pre-prod|sandbox|demo|beta|alpha|canary|try|innovation)([-.]|$)' && score=$((score+80))
    echo "$host" | grep -qiE '(^|\.)(internal|intranet|corp|private|vpn|sso|auth|login|id|identity|okta|saml|client|kuma)([-.]|$)' && score=$((score+75))
    echo "$host" | grep -qiE '(^|\.)(jenkins|gitlab|github|git|ci|cd|build|deploy|harbor|registry|nexus|artifactory|sonar)([-.]|$)' && score=$((score+70))
    echo "$host" | grep -qiE '(^|\.)(db|database|mysql|postgres|mongo|redis|elastic|kibana|grafana|prometheus|monitor|health|clinic)([-.]|$)' && score=$((score+65))
    echo "$url" | grep -qE ':[0-9]{2,5}(/|$)' && score=$((score+40))  # non-default port
    echo "$host" | grep -qiE '(^|\.)(app|apps|mobile|m|cdn|static|assets|img|media)([-.]|$)' && score=$((score+10))
    # Any non-apex subdomain gets a base boost so they outrank bare apex
    apex="${TARGET}"
    if [ "$host" = "$apex" ] || [ "$host" = "www.$apex" ]; then
      score=$((score+5))
    else
      score=$((score+25))
    fi
    echo "${score} ${url}"
  done < "$RANK_INPUT" | sort -rn | tee "$RD/live/interesting_ranked.txt" | awk '$1>=40 {print $2}' > "$RD/live/interesting.txt" || true
  # Ensure we always have something: if nothing scored high, take top 15 by score
  if [ ! -s "$RD/live/interesting.txt" ]; then
    awk '{print $2}' "$RD/live/interesting_ranked.txt" 2>/dev/null | head -15 > "$RD/live/interesting.txt" || true
  fi
  echo "✅ Interesting hosts (score>=40): $(wc -l < "$RD/live/interesting.txt" 2>/dev/null || echo 0) / total live $(wc -l < "$RD/live/live.txt" 2>/dev/null || echo 0)"
  head -10 "$RD/live/interesting_ranked.txt" 2>/dev/null | sed 's/^/   /' || true
fi
# Unified scan order for ALL downstream tools: interesting first, then the rest.
# Single source of truth — avoids each scanner re-implementing prioritization.
: > "$RD/live/scan_order.txt"
if [ -s "$RD/live/interesting.txt" ]; then
  cat "$RD/live/interesting.txt" > "$RD/live/scan_order.txt"
  grep -Fxv -f "$RD/live/interesting.txt" "$RD/live/live.txt" >> "$RD/live/scan_order.txt" 2>/dev/null || true
elif [ -s "$RD/live/live.txt" ]; then
  cp "$RD/live/live.txt" "$RD/live/scan_order.txt"
fi
echo "✅ scan_order.txt ready: $(wc -l < "$RD/live/scan_order.txt" 2>/dev/null || echo 0) hosts (interesting-first)"
# Cap list for expensive Tor-bound steps when surface is large or unverified
head -20 "$RD/live/scan_order.txt" > "$RD/live/expensive_targets.txt" 2>/dev/null || true
probe_path=$(cat "$RD/meta/live_probe_path.txt" 2>/dev/null || echo verified)
case "$probe_path" in
  dns-seed|ports-enriched|apex-seed)
    head -15 "$RD/live/scan_order.txt" > "$RD/live/expensive_targets.txt" 2>/dev/null || true
    echo "⚠️ Unverified live path ($probe_path) - expensive steps use top $(wc -l < "$RD/live/expensive_targets.txt") hosts"
    ;;
esac

# --- Critical host seeds (2026-09-13) ---
# Tor live-probe can drop high-value hosts seen in older runs
# (onlinedoctor / photo). Inject additive seeds for crawl lists.
TARGET_ROOT="${TARGET}"
: > "$RD/live/critical_seeds.txt"
for ch in \
  "$TARGET_ROOT" \
  "www.$TARGET_ROOT" \
  "onlinedoctor.$TARGET_ROOT" \
  "photo.$TARGET_ROOT" \
  "api.$TARGET_ROOT" \
  "app.$TARGET_ROOT"
do
  [ -z "$ch" ] && continue
  echo "$ch" >> "$RD/subdomains/all_subs.txt"
  echo "https://$ch" >> "$RD/live/critical_seeds.txt"
  echo "http://$ch" >> "$RD/live/critical_seeds.txt"
done
sort -u "$RD/subdomains/all_subs.txt" -o "$RD/subdomains/all_subs.txt" 2>/dev/null || true
sort -u "$RD/live/critical_seeds.txt" -o "$RD/live/critical_seeds.txt" 2>/dev/null || true
{
  cat "$RD/live/critical_seeds.txt" 2>/dev/null
  cat "$RD/live/expensive_targets.txt" 2>/dev/null
} | awk 'NF && !seen[$0]++' > /tmp/expensive_merged.txt
# BUGFIX (2026-09-14): these three merges used to `mv` unconditionally.
# If this step is killed (timeout-minutes) mid-write, or any upstream
# `cat` in the { } group above fails, the merged temp file can end up
# empty - and an unconditional mv then replaces a previously-good,
# non-empty file with nothing. Only replace when the new merge
# actually has content; otherwise leave the existing file untouched.
[ -s /tmp/expensive_merged.txt ] && mv /tmp/expensive_merged.txt "$RD/live/expensive_targets.txt"
{
  cat "$RD/live/critical_seeds.txt" 2>/dev/null
  cat "$RD/live/scan_order.txt" 2>/dev/null
} | awk 'NF && !seen[$0]++' > /tmp/scan_order_merged.txt
[ -s /tmp/scan_order_merged.txt ] && mv /tmp/scan_order_merged.txt "$RD/live/scan_order.txt"
{
  cat "$RD/live/live.txt" 2>/dev/null
  cat "$RD/live/critical_seeds.txt" 2>/dev/null
} | awk 'NF && !seen[$0]++' > /tmp/live_merged.txt
[ -s /tmp/live_merged.txt ] && mv /tmp/live_merged.txt "$RD/live/live.txt"
echo "critical_seeds=$(wc -l < "$RD/live/critical_seeds.txt" 2>/dev/null || echo 0)" > "$RD/meta/critical_seeds_note.txt"
echo "✅ Critical seeds injected: $(wc -l < "$RD/live/critical_seeds.txt") URLs (live now $(wc -l < "$RD/live/live.txt"))"

