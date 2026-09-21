#!/usr/bin/env bash
set -eo pipefail

# --- Realistic browser header set (2026-09-14) ---
# WAFs at enterprise targets (Cloudflare/Akamai/Imperva-class) fingerprint far
# beyond just the User-Agent string - a request missing the Accept/
# Accept-Language/Accept-Encoding headers a real browser always sends is an
# easy, cheap "this is a scanner" signal on its own. Adding the rest of a
# normal Chrome request's header set won't defeat TLS/JA3-level fingerprinting
# (that needs a different HTTP client entirely, out of scope for this fix),
# but it does close the trivial header-based detection layer for free.
BROWSER_HEADERS=(
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.9"
  -H "Accept-Encoding: gzip, deflate, br"
)

RD="results/$TIMESTAMP"
# Prefer DNS-confirmed hosts (resolved.txt) over raw candidates — probing
# unresolved names wastes Tor circuits and was a major source of empty live.json.
INPUT="$RD/subdomains/resolved.txt"
[ -s "$INPUT" ] || INPUT="$RD/subdomains/all_subs.txt"
[ -s "$INPUT" ] || { echo "$TARGET" > /tmp/fallback.txt; INPUT=/tmp/fallback.txt; }
# Normalize to scheme URLs (httpx -u bare-host is flaky under proxychains)
: > /tmp/probe_input_urls.txt
{
  echo "$TARGET"
  echo "www.$TARGET"
  cat "$INPUT"
} | awk 'NF && !seen[$0]++' | while IFS= read -r h; do
  h="$(echo "$h" | tr -d '\r' | xargs)"; [ -z "$h" ] && continue
  case "$h" in
    http://*|https://*) echo "$h" ;;
    *) echo "https://$h"; echo "http://$h" ;;
  esac
done > /tmp/probe_input_urls.txt
INPUT=/tmp/probe_input_urls.txt
AUTH_ARGS=()
[ -n "$AUTH_COOKIE" ] && AUTH_ARGS+=(-H "Cookie: $AUTH_COOKIE")
[ -n "$AUTH_HEADER" ] && AUTH_ARGS+=(-H "$AUTH_HEADER")

# BUGFIX: confirmed on THREE separate real runs against three different
# targets (7, 68, and 159 real candidates respectively, so this isn't a
# scale/timeout issue) that httpx's bulk "-l file -json -o file" mode
# through proxychains4 deterministically writes ZERO bytes to its output,
# even when several candidates are genuinely live. The diagnostic probe
# further down (meta/httpx_verbose_diag.txt) proved the opposite: a lone
# "httpx -u <host>" call over the exact same Tor circuit gets a completely
# normal response every time. Rather than keep trusting "-l" mode, probe
# each host with its own "-u" call (the mode actually proven to work) with
# bounded concurrency so this stays fast, and a self-tracked time budget
# (bash's $SECONDS, since an external `timeout` can't wrap a shell
# function) so a run with many real subdomains can never blow this step's
# 12-minute limit - it just stops early and keeps whatever it already
# found instead of losing everything the way "-l" mode's all-or-nothing
# output file did.
# BUGFIX 2026-09-08: Parallel append (>>) of JSON lines from many
# background jobs into one file is NOT atomic. Under Tor + high
# concurrency the file becomes corrupted NDJSON (partial lines /
# interleaving), so later `jq` silently produces nothing and
# live.txt ends up empty even when hosts were actually live.
# Fix: each probe writes to its own temp file, then we safely
# concatenate. Also drop concurrency from 12 → 4 because Tor
# cannot sustain that many simultaneous new circuits on a single
# process without high failure rates (confirmed on real runs).
probe_hosts() {
  local input_file="$1" output_file="$2" timeout_s="$3" retries_n="$4" concurrency="$5" max_duration="$6"
  local tmp_dir
  tmp_dir=$(mktemp -d)
  : > "$output_file"
  local running=0 start_sec=$SECONDS idx=0
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    if [ -n "$max_duration" ] && [ $((SECONDS - start_sec)) -ge "$max_duration" ]; then
      echo "ℹ️ probe_hosts: ${max_duration}s time budget reached for $output_file - stopping early with partial results" >> "$RD/logs/httpx.log"
      break
    fi
    idx=$((idx + 1))
    # Small random jitter before each launch (2026-09-14): a burst of dozens
    # of near-simultaneous new connections from one IP is itself a bot-like
    # rate signal to a WAF, independent of headers - spreading launches out
    # by a few hundred ms costs almost nothing at this concurrency level.
    sleep "0.$((RANDOM % 4 + 1))" 2>/dev/null || true
    (
      # BUGFIX: this call feeds live/tech.json (see the second probe_hosts
      # invocation below) but was missing -td (tech-detect) entirely, so
      # httpx's JSON output never had a "tech" field to begin with -
      # confirmed on a real run (superdrug.com) where tech.json came back
      # completely empty (0 bytes) and every downstream consumer (Nuclei's
      # -as tech-aware pass, WordPress detection, AI triage context, and
      # smart-fuzzing's wolf_selector.py) silently got nothing.
      out_file="$tmp_dir/$(printf '%05d' $idx).json"
      t_start=$(date +%s)
      tor_exit=0
      proxychains4 -q httpx -u "$host" -silent -status-code -title -web-server -ip -cdn -td -follow-redirects "${BROWSER_HEADERS[@]}"                   -H "User-Agent: $SCAN_USER_AGENT" "${AUTH_ARGS[@]}"                   -timeout "$timeout_s" -retries "$retries_n" -json                   2>>"$RD/logs/httpx.log" > "$out_file" || tor_exit=$?
      t_end=$(date +%s)
      # ROOT CAUSE FOUND AND FIXED (2026-09-20, real runs against
      # capital.com and datacamp.com): the -v flag added in a prior
      # diagnostic commit is INCOMPATIBLE with -silent in this httpx
      # version - it caused a fatal "[FTL] verbose flag is incompatible
      # with silent flag" error on 100% of calls (exit=1, zero output),
      # both Tor and DIRECT, on every host. That -v flag was itself the
      # bug causing the empty tech.json this diagnostic commit was
      # trying to investigate - confirmed by the literal FTL message in
      # logs/httpx.log across 1200+/4000+ lines in both real runs.
      # -v has been removed. The [diag] exit-code/timing logging below
      # is kept (it's harmless and still useful going forward), but
      # -v specifically must never be reintroduced alongside -silent -
      # if per-host verbosity is ever needed again, use -debug or drop
      # -silent instead, never both -v and -silent together.
      echo "[diag] pass=$output_file host=$host path=tor exit=$tor_exit duration=$((t_end - t_start))s out_bytes=$(wc -c < "$out_file" 2>/dev/null || echo 0)" >> "$RD/logs/httpx.log"
      # Per-host DIRECT fallback: Tor is kept as the default path
      # deliberately (it was added to get past IP-based blocking of
      # well-known cloud/CI ranges that some WAFs reject outright), but
      # proxychains/Tor is also documented elsewhere in this pipeline as
      # occasionally returning 0 bytes for an entire target with no error
      # (see zero-track-hunter.yml's "DIRECT first" nuclei comment).
      # Rather than picking one path pipeline-wide, retry DIRECT only for
      # the specific host that Tor actually failed on - this keeps Tor's
      # IP-diversity benefit where it works and stops individual hosts
      # from silently going empty when it doesn't.
      if [ ! -s "$out_file" ]; then
        echo "ℹ️ Tor probe returned nothing for $host, retrying DIRECT..." >> "$RD/logs/httpx.log"
        t_start=$(date +%s)
        direct_exit=0
        httpx -u "$host" -silent -status-code -title -web-server -ip -cdn -td -follow-redirects "${BROWSER_HEADERS[@]}"               -H "User-Agent: $SCAN_USER_AGENT" "${AUTH_ARGS[@]}"               -timeout "$timeout_s" -retries "$retries_n" -json               2>>"$RD/logs/httpx.log" > "$out_file" || direct_exit=$?
        t_end=$(date +%s)
        echo "[diag] pass=$output_file host=$host path=direct exit=$direct_exit duration=$((t_end - t_start))s out_bytes=$(wc -c < "$out_file" 2>/dev/null || echo 0)" >> "$RD/logs/httpx.log"

        # DECISIVE COMPARISON (added after inconclusive runs on
        # capital.com/datacamp.com/okx.com - out_bytes=0/exit=0 on both
        # Tor and DIRECT, but no controlled same-URL comparison against
        # a non-Go tool existed yet). If httpx STILL has nothing after
        # both paths, immediately curl the EXACT same URL and log the
        # result right next to httpx's failure. This settles the
        # Go-TLS-fingerprint-rejection hypothesis with a direct,
        # same-request comparison instead of inferring it from separate
        # baseline.py runs on different hosts.
        if [ ! -s "$out_file" ]; then
          curl_status=$(curl -sk --max-time "$timeout_s" -o /dev/null -w "%{http_code}" "$host" 2>>"$RD/logs/httpx.log")
          curl_exit=$?
          echo "[diag-decisive] host=$host httpx_bytes=0(both_paths) curl_exit=$curl_exit curl_status=\"$curl_status\"" >> "$RD/logs/httpx.log"
          # REAL FALLBACK, not just diagnosis: if curl got a real status
          # code where httpx got nothing at all, write a minimal
          # NDJSON-compatible line so this host isn't simply invisible
          # downstream. No "tech" field (curl can't fingerprint that -
          # only httpx's -td can), but status_code/url/host_curl_fallback
          # is genuine, real data instead of the host silently vanishing
          # from live.json/tech.json entirely.
          if [ "$curl_exit" = "0" ] && [ -n "$curl_status" ] && [ "$curl_status" != "000" ]; then
            echo "{\"url\":\"$host\",\"status_code\":$curl_status,\"host_curl_fallback\":true}" > "$out_file"
            echo "ℹ️ httpx got nothing for $host on both paths, but curl confirmed status=$curl_status - wrote a minimal curl-fallback record instead of leaving this host empty" >> "$RD/logs/httpx.log"
          fi
        fi
      fi
    ) &
    running=$((running + 1))
    if [ "$running" -ge "$concurrency" ]; then
      wait -n 2>/dev/null || wait
      running=$((running - 1))
    fi
  done < "$input_file"
  wait
  # Safe merge: only non-empty valid-looking lines
  cat "$tmp_dir"/*.json 2>/dev/null | grep -v '^\s*$' >> "$output_file" || true
  rm -rf "$tmp_dir"
}

probe_hosts "$INPUT" "$RD/live/live.json" 15 2 4 360
# NDJSON-safe extraction (one JSON object per line)
if [ -s "$RD/live/live.json" ]; then
  jq -r 'select(. != null) | (.url // .input // empty)' "$RD/live/live.json" 2>/dev/null \
    | grep -v '^\s*$' | sort -u > "$RD/live/live.txt" || true
else
  : > "$RD/live/live.txt"
fi
echo "ℹ️ Live hosts after primary probe: $(wc -l < "$RD/live/live.txt" 2>/dev/null || echo 0)"

# A run's assigned Tor circuit can be individually flaky even when
# Tor itself is confirmed up and a lightweight single curl through
# it succeeds - seen for real: 0 live hosts from httpx AND 0 from
# asnmap in the same run, both with a completely empty log (no
# error at all), while a plain diagnostic curl on the same circuit
# got a normal 404/200. That signature means the bulk multi-
# connection tools hit transient circuit instability the single
# request didn't. One retry on a forced-fresh circuit is cheap
# insurance against losing the entire rest of the pipeline to one
# unlucky circuit, since everything downstream (URLs/JS/etc) reads
# from live.txt.
if [ ! -s "$RD/live/live.txt" ] && [ -s "$INPUT" ]; then
  echo "⚠️ 0 live hosts despite non-empty input - forcing a fresh Tor circuit and retrying httpx once..."
  sudo pkill -HUP -x tor 2>/dev/null || true
  sleep 8
  probe_hosts "$INPUT" "$RD/live/live.json" 15 2 4 150
  if [ -s "$RD/live/live.json" ]; then
    jq -r 'select(. != null) | (.url // .input // empty)' "$RD/live/live.json" 2>/dev/null \
      | grep -v '^\s*$' | sort -u > "$RD/live/live.txt" || true
  else
    : > "$RD/live/live.txt"
  fi
  [ -s "$RD/live/live.txt" ] && echo "✅ Retry on fresh circuit recovered $(wc -l < "$RD/live/live.txt") live host(s)" || echo "ℹ️ Retry also found nothing - will try DIRECT (no-Tor) fallback"
fi

# ================================================================
# DIRECT FALLBACK (2026-09-08) — confirmed on kyc.com real run:
# - Apex https://kyc.com returned 301 via curl health check
# - naabu saw open 80/443 on multiple hosts
# - Tor/proxied httpx still produced 0 live hosts (timeouts on many
#   candidates; parallel-write bugs fixed separately)
# When Tor path yields empty live.txt but we have DNS candidates,
# probe WITHOUT proxychains so the rest of the pipeline is not blind.
# Results are still in-scope hosts only (same INPUT list).
# ================================================================
if [ ! -s "$RD/live/live.txt" ] && [ -s "$INPUT" ]; then
  echo "🔄 DIRECT fallback: probing without Tor (Tor path returned 0 live hosts)..."
  probe_hosts_direct() {
    local input_file="$1" output_file="$2" timeout_s="$3" retries_n="$4" concurrency="$5" max_duration="$6"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    : > "$output_file"
    local running=0 start_sec=$SECONDS idx=0
    while IFS= read -r host; do
      [ -z "$host" ] && continue
      # Normalize bare hostnames to https://
      case "$host" in
        http://*|https://*) ;;
        *) host="https://$host" ;;
      esac
      if [ -n "$max_duration" ] && [ $((SECONDS - start_sec)) -ge "$max_duration" ]; then
        echo "ℹ️ probe_hosts_direct: ${max_duration}s budget reached" >> "$RD/logs/httpx.log"
        break
      fi
      idx=$((idx + 1))
      sleep "0.$((RANDOM % 4 + 1))" 2>/dev/null || true
      (
        httpx -u "$host" -silent -status-code -title -web-server -ip -cdn -follow-redirects "${BROWSER_HEADERS[@]}"                     -H "User-Agent: $SCAN_USER_AGENT" "${AUTH_ARGS[@]}"                     -timeout "$timeout_s" -retries "$retries_n" -json                     2>>"$RD/logs/httpx_direct.log" > "$tmp_dir/$(printf '%05d' $idx).json" || true
      ) &
      running=$((running + 1))
      if [ "$running" -ge "$concurrency" ]; then
        wait -n 2>/dev/null || wait
        running=$((running - 1))
      fi
    done < "$input_file"
    wait
    cat "$tmp_dir"/*.json 2>/dev/null | grep -v '^\s*$' >> "$output_file" || true
    rm -rf "$tmp_dir"
  }
  # Also force apex + www first in a priority list
  {
    echo "$TARGET"
    echo "www.$TARGET"
    cat "$INPUT"
  } | awk 'NF && !seen[$0]++' > /tmp/direct_probe_input.txt
  probe_hosts_direct /tmp/direct_probe_input.txt "$RD/live/live_direct.json" 12 2 8 180
  if [ -s "$RD/live/live_direct.json" ]; then
    jq -r 'select(. != null) | (.url // .input // empty)' "$RD/live/live_direct.json" 2>/dev/null                 | grep -v '^\s*$' | sort -u > "$RD/live/live.txt" || true
    cp "$RD/live/live_direct.json" "$RD/live/live.json" 2>/dev/null || true
    echo "✅ DIRECT fallback recovered $(wc -l < "$RD/live/live.txt") live host(s) (no Tor)" | tee -a "$RD/meta/scan_health_warning.txt"
    echo "direct" > "$RD/meta/live_probe_path.txt"
  else
    echo "ℹ️ DIRECT fallback also found 0 live hosts" | tee -a "$RD/logs/httpx_direct.log"
    # Last resort recovery: NEVER leave downstream blind when DNS already
    # confirmed subdomains (or open ports). Real runs (superdrug, kec, kyc)
    # proved Tor+httpx can return 0 AND GitHub-runner direct can be WAF-blocked
    # (403) while the hosts are still real. Seed from evidence we already have.
    : > "$RD/live/live.txt"
    # 1) Every DNS-resolved subdomain → try both schemes as candidates
    if [ -s "$RD/subdomains/resolved.txt" ]; then
      while IFS= read -r h; do
        h="$(echo "$h" | tr -d '\r' | xargs)"; [ -z "$h" ] && continue
        echo "https://$h" >> "$RD/live/live.txt"
        echo "http://$h" >> "$RD/live/live.txt"
      done < "$RD/subdomains/resolved.txt"
    fi
    # 2) Apex + www always
    echo "https://$TARGET" >> "$RD/live/live.txt"
    echo "https://www.$TARGET" >> "$RD/live/live.txt"
    echo "http://$TARGET" >> "$RD/live/live.txt"
    echo "http://www.$TARGET" >> "$RD/live/live.txt"
    # 3) Hosts that naabu already proved have open ports (written later into
    # ports.txt in the next step — at this point we may not have it yet, so
    # also accept all_subs as soft candidates if resolved was empty)
    if [ ! -s "$RD/live/live.txt" ] && [ -s "$RD/subdomains/all_subs.txt" ]; then
      while IFS= read -r h; do
        h="$(echo "$h" | tr -d '\r' | xargs)"; [ -z "$h" ] && continue
        echo "https://$h" >> "$RD/live/live.txt"
      done < "$RD/subdomains/all_subs.txt"
    fi
    sort -u -o "$RD/live/live.txt" "$RD/live/live.txt"
    n=$(wc -l < "$RD/live/live.txt" 2>/dev/null || echo 0)
    apex_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 -H "User-Agent: $SCAN_USER_AGENT" "https://$TARGET/" 2>/dev/null || echo "000")
    apex_code="${apex_code: -3}"
    echo "⚠️ Probe failed (Tor+direct empty). Seeded live.txt with $n DNS/port-backed candidates (apex curl=$apex_code). Downstream still runs; treat as unverified-live." | tee -a "$RD/meta/scan_health_warning.txt"
    echo "dns-seed" > "$RD/meta/live_probe_path.txt"
  fi
else
  [ -s "$RD/live/live.txt" ] && echo "tor" > "$RD/meta/live_probe_path.txt"
fi

# Best-effort second pass: only the confirmed real subdomains above are
# allowed to consume this step's full budget. ASN/CIDR-derived IPs are
# a bonus, capped at a much smaller sample and hard-bounded by the same
# self-tracked time budget so a slow/unresponsive batch of them can never
# crowd out or block the real subdomain results above - worst case it's
# simply cut short and whatever it found so far is kept.
if [ -s "$RD/subdomains/asn_ips.txt" ]; then
  ASN_PROBE_INPUT="/tmp/asn_probe_input.txt"
  head -300 "$RD/subdomains/asn_ips.txt" > "$ASN_PROBE_INPUT" || true
  asn_kept=$(wc -l < "$ASN_PROBE_INPUT" 2>/dev/null || echo 0)
  echo "ℹ️ Probing up to $asn_kept ASN/CIDR-derived candidate(s) separately (best-effort, max 2 minutes, won't affect the real-subdomain results above)"
  probe_hosts "$ASN_PROBE_INPUT" "$RD/live/live_asn.json" 10 1 4 120
  if [ -s "$RD/live/live_asn.json" ]; then
    jq -r '.url // .input' "$RD/live/live_asn.json" 2>/dev/null | grep -v '^\s*$' >> "$RD/live/live.txt" || true
    sort -u -o "$RD/live/live.txt" "$RD/live/live.txt"
    echo "✅ ASN/CIDR pass added $(jq -r '.url // .input' "$RD/live/live_asn.json" 2>/dev/null | grep -c .) more live host(s)"
  fi
fi

jq -r 'select(.cdn_name != null) | "\(.url) -> \(.cdn_name)"' "$RD/live/live.json" > "$RD/live/waf.txt" 2>/dev/null || true
# BUGFIX: tech-detect used the same broken "-l" bulk mode as the main probe
# above - switched to the same proven-working per-host loop. live.txt is
# small at this point (confirmed hosts only), so no time budget is needed.
probe_hosts "$RD/live/live.txt" "$RD/live/tech.json" 15 2 4 ""
echo "✅ Live hosts: $(wc -l < "$RD/live/live.txt")"
# Classify verified vs unverified for operators + downstream caps
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
live_count=$(wc -l < "$RD/live/live.txt" 2>/dev/null || echo 0)
input_count=$(wc -l < "$INPUT" 2>/dev/null || echo 0)
if [ "$live_count" -eq 0 ] && [ "$input_count" -gt 0 ] && [ ! -s "$RD/meta/scan_health_warning.txt" ]; then
  echo "::warning::0 live hosts found despite $input_count candidate(s) in the input ($INPUT) - this is NOT a normal clean-scan result. Confirmed causes seen in real runs: a discovery tool silently losing hosts upstream, or the target/WAF blocking this runner's IP. Check $RD/logs/httpx.log (even if empty - that itself is a clue) before trusting any downstream '0 findings' from this run."
  echo "⚠️ 0 LIVE HOSTS FROM $input_count CANDIDATE(S) - flagging for manual review, see logs/httpx.log" >> "$RD/logs/httpx.log"
  mkdir -p "$RD/meta"
  probe_host="$(head -1 "$INPUT" | tr -d '\r' | xargs)"
  [ -z "$probe_host" ] && probe_host="$TARGET"
  case "$probe_host" in http*://*) probe_url="$probe_host/" ;; *) probe_url="https://$probe_host/" ;; esac
  diag_status=$(proxychains4 -q curl -sk -o /dev/null --max-time 12 -w "%{http_code}" "$probe_url" 2>>/tmp/diag_curl.log || echo "000")
  diag_status="${diag_status: -3}"
  # Also check the bare apex separately - a target can have the apex domain
  # working fine (redirect, real site) while the SPECIFIC candidate
  # subdomains httpx actually tried behave completely differently (blocked,
  # or simply not a normal web-facing host at all, e.g. an internal/
  # websocket-only service picked up by permutation guessing).
  apex_status=$(proxychains4 -q curl -sk -o /dev/null --max-time 12 -w "%{http_code}" "https://$TARGET/" 2>>/tmp/diag_curl.log || echo "000")
  apex_status="${apex_status: -3}"
  diag_note="Direct diagnostic probe to $probe_url (the actual first candidate httpx tried) returned status $diag_status. For comparison, the bare apex https://$TARGET/ returned $apex_status."
  if [ "$diag_status" = "000" ]; then
    diag_note="$diag_note This runner could not complete a TLS/TCP connection to that specific candidate at all - strong signal of network-level blocking, or the candidate simply isn't a normal HTTP-facing host (e.g. an internal/websocket-only service picked up by subdomain guessing)."
  elif [ "$diag_status" = "403" ] || [ "$diag_status" = "429" ]; then
    diag_note="$diag_note A $diag_status here is a classic WAF/rate-limit block signature specifically on this candidate."
  elif [ "$diag_status" != "000" ] && [ "$apex_status" != "000" ]; then
    diag_note="$diag_note Both probes got a real HTTP response, so this may not be a network block at all - check whether httpx's own flags/redirect-following are the actual issue here, not just assume WAF blocking."
  fi
  echo "0 live hosts found despite $input_count candidate(s) - the target may be blocking/rate-limiting this runner's IP rather than genuinely having no findings. Do NOT treat a clean-looking report below as confirmation of security. $diag_note" > "$RD/meta/scan_health_warning.txt"
  # BUGFIX/DIAGNOSTIC: the curl-based check above proves the target itself
  # is reachable through this same proxy chain, but every httpx call runs
  # with -silent, which suppresses httpx's OWN error/debug output - so when
  # httpx alone returns nothing (confirmed on real runs against two
  # different targets: live.json ends up 0 bytes both times) we have no way
  # to see WHY httpx specifically failed where curl on the identical host/
  # proxy succeeded. Re-run httpx just once, on just this one host, WITHOUT
  # -silent, so its own reported error (SOCKS handshake failure, DNS
  # failure, TLS failure, a redirect it refuses to follow, etc.) is captured
  # for the next run to actually pinpoint the real cause instead of
  # re-confirming what curl already showed.
  proxychains4 -q httpx -u "$probe_url" -status-code -title -follow-redirects -H "User-Agent: $SCAN_USER_AGENT" -timeout 15 -retries 2 -debug > "$RD/meta/httpx_verbose_diag.txt" 2>&1 || true
fi

