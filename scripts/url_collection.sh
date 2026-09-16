#!/usr/bin/env bash
set -eo pipefail

RD="results/$TIMESTAMP"

# --- Adaptive timeout scaling for large targets (2026-09-14) ---
# Every timeout below was tuned against small/medium targets (~10-100
# subdomains). Confirmed on a real run against binance.com (12,810 confirmed
# subdomains, 23,251 live hosts): wayback/gau/katana/hakrawler/gospider all
# hit their fixed ceiling before covering a meaningful fraction of the
# surface (gau explicitly logged "killed by timeout"), leaving only 533
# total URLs - a collection failure, not evidence the target has few URLs.
# Double the per-tool timeouts once the live surface crosses 1000 hosts so
# large targets get a proportionally longer collection window. The
# corresponding step's timeout-minutes was raised (30 -> 50) to give this
# room without hitting the job-level step timeout instead.
LIVE_COUNT=$(wc -l < "$RD/live/live.txt" 2>/dev/null || echo 0)
TIMEOUT_SCALE=1
[ "${LIVE_COUNT:-0}" -gt 1000 ] 2>/dev/null && TIMEOUT_SCALE=2
scale_timeout() { echo $(( $1 * TIMEOUT_SCALE )); }
echo "ℹ️ URL Collection timeout scale: x${TIMEOUT_SCALE} (live hosts=${LIVE_COUNT:-0})"

INPUT="$RD/subdomains/all_subs.txt"
[ -s "$INPUT" ] || { echo "$TARGET" > /tmp/fallback.txt; INPUT=/tmp/fallback.txt; }
AUTH_ARGS=()
[ -n "$AUTH_COOKIE" ] && AUTH_ARGS+=(-H "Cookie: $AUTH_COOKIE")
[ -n "$AUTH_HEADER" ] && AUTH_ARGS+=(-H "$AUTH_HEADER")
echo "🔍 Wayback..."
# BUGFIX: this used to feed waybackurls the narrow discovered-subdomains
# list instead of the target's root domain. waybackurls queries the
# Wayback CDX API with matchType=domain, which ALREADY expands to every
# subdomain archive.org has ever seen for whatever host you give it - so
# feeding it 14 individually-discovered (often internal/test-looking,
# e.g. "api-website-internal.capital.com") subdomains one by one is
# both redundant with, and strictly narrower than, just querying the
# root domain once. Confirmed on a real run: archive.org has no history
# for obscure internal subdomains like that (0 results, expected), which
# this fix stops relying on entirely.
#
# BUGFIX 2: 150s was too short. Confirmed on a real run against a large,
# 26-year-old domain (superdrug.com, live since 2000): a direct,
# LIMITED (limit=5) diagnostic query to the exact same CDX API returned
# real data instantly, proving the API itself is reachable and has
# plenty of history - but waybackurls asks for the ENTIRE unlimited
# history in one request, which for a domain this old/large can
# legitimately take longer than 150s to fully download, so our own
# timeout was killing it before it ever got a response to write out
# (0 bytes in both the output file AND the log - a killed process gets
# no chance to log anything). 300s gives large/old domains a fair shot;
# the explicit exit-code check makes it obvious next time if 300s still
# isn't enough (124 = timeout killed it) versus a genuine clean-but-
# empty completion.
# GHA runs bash -e: timeout exit 124 would abort the whole step.
timeout $(scale_timeout 300) bash -c 'echo "$TARGET" | waybackurls' > "$RD/urls/wayback.txt" 2>>"$RD/logs/wayback.log" || wb_exit=$?
wb_exit=${wb_exit:-0}
if [ "$wb_exit" -eq 124 ]; then
  echo "⚠️ waybackurls killed by 300s timeout (partial/empty possible)" | tee -a "$RD/logs/wayback.log"
fi
# Diagnostic: confirmed via httpx that this runner's outbound network is
# fine in general, but public archive APIs (unlike the target) are a
# DIFFERENT, third-party dependency with their own independent rate-
# limiting - GitHub Actions' shared runner IP ranges are commonly
# throttled by exactly these services due to abuse from unrelated
# workflows. If wayback.txt/gau.txt come up empty again, this captures
# the CDX API's raw response so the next run can tell "genuinely no
# archived history" apart from "this runner's IP got rate-limited".
if [ ! -s "$RD/urls/wayback.txt" ]; then
  echo "ℹ️ waybackurls returned empty - multi-strategy CDX fallback..."
  # Diag (may return 503 when archive.org is overloaded - capital.com run)
  cdx_code=$(curl -sL --max-time 20 -o "$RD/meta/archive_cdx_diag.txt" -w "%{http_code}" \
    "https://web.archive.org/cdx/search/cdx?url=$TARGET/*&output=json&limit=5&filter=statuscode:200" 2>>"$RD/logs/wayback.log" || echo "000")
  echo "HTTP_STATUS:${cdx_code}" | tee -a "$RD/meta/archive_cdx_diag.txt"
  # Strategy A: text fl=original (retry once on 503)
  for attempt in 1 2; do
    curl -sL --max-time 90 \
      "https://web.archive.org/cdx/search/cdx?url=$TARGET/*&output=text&fl=original&collapse=urlkey&limit=5000" \
      2>>"$RD/logs/wayback.log" | grep -Eo 'https?://[^[:space:]"]+' | sort -u > "$RD/urls/wayback.txt" || true
    [ -s "$RD/urls/wayback.txt" ] && break
    echo "ℹ️ CDX attempt $attempt empty - sleep 5s and retry..."
    sleep 5
  done
  # Strategy B: JSON parse
  if [ ! -s "$RD/urls/wayback.txt" ]; then
    echo "ℹ️ CDX text empty - trying JSON CDX parse..."
    curl -sL --max-time 90 -o /tmp/cdx.json \
      "https://web.archive.org/cdx/search/cdx?url=$TARGET/*&output=json&fl=original&collapse=urlkey&limit=5000" \
      2>>"$RD/logs/wayback.log" || true
    if [ -s /tmp/cdx.json ]; then
      jq -r '.[1:][]? | if type=="array" then .[0] else . end' /tmp/cdx.json 2>/dev/null \
        | grep -Eo 'https?://[^[:space:]"]+' | sort -u > "$RD/urls/wayback.txt" || true
    fi
  fi
  # Strategy C: apex + www separately
  if [ ! -s "$RD/urls/wayback.txt" ]; then
    for host in "$TARGET" "www.$TARGET"; do
      curl -sL --max-time 45 \
        "https://web.archive.org/cdx/search/cdx?url=${host}/*&output=text&fl=original&collapse=urlkey&limit=2000" \
        2>>"$RD/logs/wayback.log" | grep -Eo 'https?://[^[:space:]"]+' >> "$RD/urls/wayback.txt" || true
    done
    sort -u -o "$RD/urls/wayback.txt" "$RD/urls/wayback.txt" 2>/dev/null || true
  fi
  # Strategy D: AlienVault OTX passive URL list (independent of archive.org)
  if [ ! -s "$RD/urls/wayback.txt" ] || [ "$(wc -l < "$RD/urls/wayback.txt")" -lt 20 ]; then
    echo "ℹ️ Fetching AlienVault OTX URL list for $TARGET..."
    curl -sL --max-time 30 \
      "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/url_list?limit=200" \
      2>>"$RD/logs/wayback.log" | jq -r '.url_list[]?.url // empty' 2>/dev/null \
      | grep -Eo 'https?://[^[:space:]"]+' >> "$RD/urls/wayback.txt" || true
    sort -u -o "$RD/urls/wayback.txt" "$RD/urls/wayback.txt" 2>/dev/null || true
  fi
  if [ -s "$RD/urls/wayback.txt" ]; then
    echo "✅ CDX/OTX fallback recovered $(wc -l < "$RD/urls/wayback.txt") URLs"
  else
    echo "ℹ️ CDX/OTX fallback empty - see meta/archive_cdx_diag.txt"
  fi
fi
touch "$RD/urls/wayback.txt" "$RD/urls/wayback_js.txt" "$RD/urls/gau.txt" "$RD/urls/waymore.txt" "$RD/urls/katana.txt" "$RD/urls/hakrawler.txt" "$RD/urls/gospider.txt" "$RD/urls/urlscan.txt" "$RD/urls/otx.txt" "$RD/urls/html_extract.txt" "$RD/urls/robots_sitemap.txt" "$RD/urls/juicy.txt"
echo "🔍 Gau..."
# bash -e: must absorb timeout 124 or step dies before katana/urlscan/merge
timeout $(scale_timeout 240) gau "$TARGET" --subs --providers wayback,commoncrawl,otx,urlscan --o "$RD/urls/gau.txt" 2>>"$RD/logs/gau.log" || gau_exit=$?
gau_exit=${gau_exit:-0}
if [ "$gau_exit" -eq 124 ]; then
  echo "⚠️ gau killed by timeout - continuing with other URL sources" | tee -a "$RD/logs/gau.log"
fi
if [ ! -s "$RD/urls/gau.txt" ]; then
  echo "ℹ️ gau --subs empty - retrying without --subs (45s)..."
  timeout $(scale_timeout 45) gau "$TARGET" --o "$RD/urls/gau.txt" 2>>"$RD/logs/gau.log" || true
fi
echo "🔍 Waymore (passive URL harvest — complements wayback/gau)..."
touch "$RD/urls/waymore.txt"
if command -v waymore >/dev/null 2>&1; then
  mkdir -p /tmp/waymore_out
  # BUGFIX (2026-09-16): "-o /tmp/waymore_out" is not a real waymore flag in
  # the installed version - confirmed in a real run's log: "waymore: error:
  # ambiguous option: -o could match -oU, -oR, -ow, -oijs". argparse's
  # prefix-matching rejected it outright, so waymore exited immediately
  # with zero output every single time this ran, silently, since the
  # surrounding `|| true` swallows the failure. -oU already writes the URL
  # list directly to the target file, so the extra flag was never needed.
  timeout $(scale_timeout 240) waymore -i "$TARGET" -mode U -oU "$RD/urls/waymore.txt" -p 2 -r 2 2>>"$RD/logs/waymore.log" || true
  if [ ! -s "$RD/urls/waymore.txt" ]; then
    find /tmp/waymore_out -type f \( -name '*.txt' -o -name '*urls*' \) -exec cat {} + 2>/dev/null \
      | grep -Eo 'https?://[^[:space:]]+' | sort -u > "$RD/urls/waymore.txt" || true
  fi
  sort -u "$RD/urls/waymore.txt" -o "$RD/urls/waymore.txt" 2>/dev/null || true
else
  echo "⚠️ waymore not installed - skipping"
fi
echo "ℹ️ waymore URLs: $(wc -l < "$RD/urls/waymore.txt" 2>/dev/null || echo 0)"
echo "🔍 Katana..."
KATANA_LIST="$RD/live/expensive_targets.txt"; [ -s "$KATANA_LIST" ] || KATANA_LIST="$RD/live/scan_order.txt"; [ -s "$KATANA_LIST" ] || KATANA_LIST="$RD/live/live.txt"
{
  cat "$KATANA_LIST" 2>/dev/null
  cat "$RD/live/critical_seeds.txt" 2>/dev/null
  echo "https://$TARGET"
  echo "https://www.$TARGET"
  echo "https://onlinedoctor.$TARGET"
  echo "https://photo.$TARGET"
} | awk 'NF && !seen[$0]++' > /tmp/katana_in.txt
[ -s /tmp/katana_in.txt ] && timeout $(scale_timeout 360) proxychains4 -q katana -list /tmp/katana_in.txt -H "User-Agent: $SCAN_USER_AGENT" "${AUTH_ARGS[@]}" -silent -depth 3 -jc -jsl -kf all -d 4 -o "$RD/urls/katana.txt" 2>>"$RD/logs/katana.log" || true
katana_n=$(wc -l < "$RD/urls/katana.txt" 2>/dev/null || echo 0)
if [ "${katana_n:-0}" -lt 50 ] && [ -s /tmp/katana_in.txt ]; then
  echo "⚠️ katana via Tor weak ($katana_n URLs) — DIRECT retry on crawl seeds..."
  timeout $(scale_timeout 300) katana -list /tmp/katana_in.txt -H "User-Agent: $SCAN_USER_AGENT" "${AUTH_ARGS[@]}" -silent -depth 3 -jc -jsl -kf all -d 4 -o /tmp/katana_direct.txt 2>>"$RD/logs/katana.log" || true
  cat /tmp/katana_direct.txt 2>/dev/null >> "$RD/urls/katana.txt" || true
  sort -u "$RD/urls/katana.txt" -o "$RD/urls/katana.txt" 2>/dev/null || true
fi
echo "ℹ️ katana URLs: $(wc -l < "$RD/urls/katana.txt" 2>/dev/null || echo 0)"
echo "🔍 Hakrawler (independent crawler - different JS/link parser than katana, catches URLs katana's config misses)..."
HAK_LIST="$RD/live/expensive_targets.txt"; [ -s "$HAK_LIST" ] || HAK_LIST="$RD/live/scan_order.txt"; [ -s "$HAK_LIST" ] || HAK_LIST="$RD/live/live.txt"
{
  cat "$HAK_LIST" 2>/dev/null
  cat "$RD/live/critical_seeds.txt" 2>/dev/null
} | awk 'NF && !seen[$0]++' > /tmp/hak_in.txt
if command -v hakrawler >/dev/null 2>&1 && [ -s /tmp/hak_in.txt ]; then
  timeout $(scale_timeout 180) proxychains4 -q bash -c "cat '/tmp/hak_in.txt' | hakrawler -subs -u -insecure -t 12 -timeout 12" > "$RD/urls/hakrawler.txt" 2>>"$RD/logs/hakrawler.log" || true
  hak_n=$(wc -l < "$RD/urls/hakrawler.txt" 2>/dev/null || echo 0)
  if [ "${hak_n:-0}" -lt 30 ]; then
    echo "⚠️ hakrawler via Tor weak ($hak_n) — DIRECT retry..."
    timeout $(scale_timeout 150) bash -c "cat '/tmp/hak_in.txt' | hakrawler -subs -u -insecure -t 12 -timeout 12" >> "$RD/urls/hakrawler.txt" 2>>"$RD/logs/hakrawler.log" || true
    sort -u "$RD/urls/hakrawler.txt" -o "$RD/urls/hakrawler.txt" 2>/dev/null || true
  fi
else
  echo "⚠️ hakrawler not installed or no live hosts - skipping"
  touch "$RD/urls/hakrawler.txt"
fi
echo "ℹ️ hakrawler URLs: $(wc -l < "$RD/urls/hakrawler.txt" 2>/dev/null || echo 0)"
echo "🔍 Gospider..."
: > "$RD/urls/gospider.txt"
GS_LIST="$RD/live/expensive_targets.txt"; [ -s "$GS_LIST" ] || GS_LIST="$RD/live/scan_order.txt"; [ -s "$GS_LIST" ] || GS_LIST="$RD/live/live.txt"
{
  cat "$GS_LIST" 2>/dev/null
  cat "$RD/live/critical_seeds.txt" 2>/dev/null
} | awk 'NF && !seen[$0]++' > /tmp/gs_in.txt
if command -v gospider >/dev/null 2>&1 && [ -s /tmp/gs_in.txt ]; then
  timeout $(scale_timeout 240) proxychains4 -q gospider -S /tmp/gs_in.txt -t 8 -d 3 --js --sitemap --robots -a -w -c 8 2>>"$RD/logs/gospider.log" | grep -Eo 'https?://[^[:space:]]+' | sort -u > "$RD/urls/gospider.txt" || true
  gs_n=$(wc -l < "$RD/urls/gospider.txt" 2>/dev/null || echo 0)
  if [ "${gs_n:-0}" -lt 50 ]; then
    echo "⚠️ gospider via Tor weak ($gs_n) — DIRECT retry..."
    timeout $(scale_timeout 200) gospider -S /tmp/gs_in.txt -t 8 -d 3 --js --sitemap --robots -a -w -c 8 2>>"$RD/logs/gospider.log" | grep -Eo 'https?://[^[:space:]]+' | sort -u >> "$RD/urls/gospider.txt" || true
    sort -u "$RD/urls/gospider.txt" -o "$RD/urls/gospider.txt" 2>/dev/null || true
  fi
else
  echo "⚠️ gospider skipped"
fi
echo "ℹ️ gospider: $(wc -l < "$RD/urls/gospider.txt" 2>/dev/null || echo 0)"
echo "🔍 urlscan.io passive (often works when archive.org rate-limits GitHub runner IPs)..."
: > "$RD/urls/urlscan.txt"
# Free search endpoint, no API key required for basic domain search
curl -s --max-time 25 -H "User-Agent: $SCAN_USER_AGENT" \
  "https://urlscan.io/api/v1/search/?q=domain:$TARGET&size=100" 2>>"$RD/logs/urlscan.log" \
  | jq -r '.results[]?.page.url // empty' 2>/dev/null | grep -E '^https?://' | sort -u > "$RD/urls/urlscan.txt" || true
echo "ℹ️ urlscan.io URLs: $(wc -l < "$RD/urls/urlscan.txt" 2>/dev/null || echo 0)"

# --- CDX JS-only pass (high-signal for source maps / bundles) ---
echo "🔍 CDX JS-focused harvest..."
: > "$RD/urls/wayback_js.txt"
curl -sL --max-time 90 \
  "https://web.archive.org/cdx/search/cdx?url=$TARGET/*&output=text&fl=original&collapse=urlkey&filter=mimetype:application/javascript&limit=3000" \
  2>>"$RD/logs/wayback.log" | grep -Eo 'https?://[^[:space:]"]+' >> "$RD/urls/wayback_js.txt" || true
curl -sL --max-time 90 \
  "https://web.archive.org/cdx/search/cdx?url=$TARGET/*.js*&output=text&fl=original&collapse=urlkey&limit=3000" \
  2>>"$RD/logs/wayback.log" | grep -Eo 'https?://[^[:space:]"]+' >> "$RD/urls/wayback_js.txt" || true
sort -u -o "$RD/urls/wayback_js.txt" "$RD/urls/wayback_js.txt" 2>/dev/null || true
echo "ℹ️ CDX JS URLs: $(wc -l < "$RD/urls/wayback_js.txt" 2>/dev/null || echo 0)"

# --- AlienVault OTX (always, additive — not only when wayback empty) ---
echo "🔍 AlienVault OTX URL list..."
: > "$RD/urls/otx.txt"
curl -sL --max-time 35 \
  "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/url_list?limit=500" \
  2>>"$RD/logs/urlscan.log" | jq -r '.url_list[]?.url // empty' 2>/dev/null \
  | grep -Eo 'https?://[^[:space:]"]+' | sort -u > "$RD/urls/otx.txt" || true
echo "ℹ️ OTX URLs: $(wc -l < "$RD/urls/otx.txt" 2>/dev/null || echo 0)"

# --- HTML page scrape: extract script/link/src/href from interesting hosts ---
# Gap: JS list was only URLs ending in .js from archives. Real apps load
# bundles via <script src> on HTML pages — scrape those from top hosts.
echo "🔍 HTML endpoint/JS extraction from prioritized hosts..."
: > "$RD/urls/html_extract.txt"
HTML_LIST="$RD/live/expensive_targets.txt"
[ -s "$HTML_LIST" ] || HTML_LIST="$RD/live/scan_order.txt"
[ -s "$HTML_LIST" ] || HTML_LIST="$RD/live/live.txt"
if [ -s "$HTML_LIST" ]; then
  head -20 "$HTML_LIST" > /tmp/html_scrape_hosts.txt
  # Always include apex roots
  echo "https://$TARGET/" >> /tmp/html_scrape_hosts.txt
  echo "https://www.$TARGET/" >> /tmp/html_scrape_hosts.txt
  sort -u -o /tmp/html_scrape_hosts.txt /tmp/html_scrape_hosts.txt
  while IFS= read -r host; do
    host="$(echo "$host" | tr -d '\r' | xargs)"; [ -z "$host" ] && continue
    # normalize to URL with path
    case "$host" in
      http://*|https://*) page="$host" ;;
      *) page="https://$host/" ;;
    esac
    case "$page" in
      */) ;;
      *) page="${page}/" ;;
    esac
    body=$(proxychains4 -q curl -sk --max-time 12 -H "User-Agent: $SCAN_USER_AGENT" "$page" 2>/dev/null || true)
    [ -n "$body" ] || body=$(curl -sk --max-time 10 -H "User-Agent: $SCAN_USER_AGENT" "$page" 2>/dev/null || true)
    [ -n "$body" ] || continue
    # Safe extract (run#14: nested quotes caused exit 2 syntax error)
    printf '%s\n' "$body" | grep -oE 'https?://[^ ]+' >> "$RD/urls/html_extract.txt" 2>/dev/null || true
    printf '%s\n' "$body" | grep -oiE 'src=/[^ >]+' | sed 's/^[Ss][Rr][Cc]=//' | while IFS= read -r ref; do
      [ -z "$ref" ] && continue
      echo "${page%/}$ref"
    done >> "$RD/urls/html_extract.txt" 2>/dev/null || true
  done < /tmp/html_scrape_hosts.txt
  sort -u -o "$RD/urls/html_extract.txt" "$RD/urls/html_extract.txt" 2>/dev/null || true
fi
echo "ℹ️ HTML-extracted URLs: $(wc -l < "$RD/urls/html_extract.txt" 2>/dev/null || echo 0)"

echo "🔍 robots.txt / sitemap.xml (cheap, often lists paths the owner didn't want indexed)..."
: > "$RD/urls/robots_sitemap.txt"
ROBOTS_LIST="$RD/live/scan_order.txt"; [ -s "$ROBOTS_LIST" ] || ROBOTS_LIST="$RD/live/live.txt"
if [ -s "$ROBOTS_LIST" ]; then
  mode="${HUNTING_MODE:-normal}"
  budget=$({ [ "$mode" = "light" ] && echo 90; } || { [ "$mode" = "aggressive" ] && echo 400; } || echo 200)
  total=$(wc -l < "$ROBOTS_LIST")
  i=0
  SECONDS=0
  while IFS= read -r host; do
    host="$(echo "$host" | tr -d '\r' | xargs)"; [ -z "$host" ] && continue
    if [ "$SECONDS" -ge "$budget" ]; then
      echo "⏱️ robots.txt/sitemap.xml: time budget reached after $i/$total host(s)"
      break
    fi
    i=$((i+1))
    proxychains4 -q curl -sk --max-time 6 -H "User-Agent: $SCAN_USER_AGENT" "${host}/robots.txt" 2>/dev/null | grep -iE '^(dis)?allow:' | sed -E 's/^[^:]*:[ \t]*//' | grep -v '^\s*$' | sed "s#^#${host}#" >> "$RD/urls/robots_sitemap.txt" || true
    proxychains4 -q curl -sk --max-time 6 -H "User-Agent: $SCAN_USER_AGENT" "${host}/sitemap.xml" 2>/dev/null | grep -oE '<loc>[^<]+</loc>' | sed -E 's/<\/?loc>//g' >> "$RD/urls/robots_sitemap.txt" || true
  done < "$ROBOTS_LIST"
fi
echo "🔄 Merging..."
: > /tmp/urls_merged.txt
for src in wayback wayback_js gau waymore katana hakrawler gospider urlscan otx html_extract robots_sitemap; do
  f="$RD/urls/${src}.txt"
  [ -s "$f" ] && cat "$f" >> /tmp/urls_merged.txt
done
sort -u -o /tmp/urls_merged.txt /tmp/urls_merged.txt 2>/dev/null || true
# Last-resort seed: if every passive/active URL source failed (superdrug
# regression: 549→0), at least put live host roots into all.txt so JS
# discovery and downstream param hunting are not totally starved.
# Always add prioritized host roots (additive) so active surface is never missing
SEED_LIST="$RD/live/expensive_targets.txt"
[ -s "$SEED_LIST" ] || SEED_LIST="$RD/live/scan_order.txt"
[ -s "$SEED_LIST" ] || SEED_LIST="$RD/live/live.txt"
if [ -s "$SEED_LIST" ]; then
  while IFS= read -r h; do
    h="$(echo "$h" | tr -d '\r' | xargs)"; [ -z "$h" ] && continue
    echo "$h" >> /tmp/urls_merged.txt
    echo "${h}/" >> /tmp/urls_merged.txt
    echo "${h}/robots.txt" >> /tmp/urls_merged.txt
    echo "${h}/sitemap.xml" >> /tmp/urls_merged.txt
    echo "${h}/.well-known/security.txt" >> /tmp/urls_merged.txt
  done < "$SEED_LIST"
fi
sort -u -o /tmp/urls_merged.txt /tmp/urls_merged.txt 2>/dev/null || true
merged_n=$(wc -l < /tmp/urls_merged.txt 2>/dev/null || echo 0)
echo "ℹ️ Merged URL candidates before uro: $merged_n"
# BUGFIX (2026-09-16): write the raw merge to all.txt *before* the slow uro
# pass, not just after it. Confirmed on binance.com (8,728 live hosts,
# TIMEOUT_SCALE=2): wayback.txt alone had 311KB of real data, but this
# step's timeout-minutes killed the whole run somewhere after the merge
# loop - all.txt was still sitting at its initial empty `touch` because
# nothing had written to it yet at that point, so all that wayback data
# never made it to disk. uro (dedup/normalize) can still improve on this
# below, but if it's slow or the step gets killed first, this early write
# means all.txt already has real content instead of nothing.
[ -s /tmp/urls_merged.txt ] && cp /tmp/urls_merged.txt "$RD/urls/all.txt"
timeout 90 uro < /tmp/urls_merged.txt > /tmp/urls_uro.txt 2>/dev/null || true
if [ -s /tmp/urls_uro.txt ]; then
  cp /tmp/urls_uro.txt "$RD/urls/all.txt"
  echo "✅ Total URLs after uro: $(wc -l < "$RD/urls/all.txt")"
else
  cp /tmp/urls_merged.txt "$RD/urls/all.txt"
  echo "⚠️ uro empty — keeping merged URLs in all.txt: $(wc -l < "$RD/urls/all.txt")"
fi
if [ ! -s "$RD/urls/all.txt" ] && [ -s /tmp/urls_merged.txt ]; then
  cp /tmp/urls_merged.txt "$RD/urls/all.txt"
  echo "⚠️ Safety restore all.txt from merge"
fi
echo "✅ Final all.txt: $(wc -l < "$RD/urls/all.txt" 2>/dev/null || echo 0) URLs"

echo "🎯 Categorizing URLs by vulnerability-relevant parameters (gf patterns)..."
: > "$RD/urls/gf_categorized.txt"
if [ -s "$RD/urls/all.txt" ] && command -v gf >/dev/null; then
  for pat in xss sqli ssrf lfi ssti idor redirect; do
    timeout 30 gf "$pat" < "$RD/urls/all.txt" 2>/dev/null | sed "s/^/[$pat] /" >> "$RD/urls/gf_categorized.txt" || true
  done
  sort -u -o "$RD/urls/gf_categorized.txt" "$RD/urls/gf_categorized.txt"
fi
echo "✅ gf-categorized candidates: $(wc -l < "$RD/urls/gf_categorized.txt" 2>/dev/null || echo 0)"

# High-value URL shortlist for hunters (params, admin, api, config, backup, js.map)
: > "$RD/urls/juicy.txt"
if [ -s "$RD/urls/all.txt" ]; then
  grep -iE '[?&](id|user|account|order|file|path|url|redirect|next|data|token|key|secret|query|search)=' "$RD/urls/all.txt" >> "$RD/urls/juicy.txt" || true
  grep -iE '/(admin|api|graphql|internal|debug|swagger|actuator|manage|console|backend)/' "$RD/urls/all.txt" >> "$RD/urls/juicy.txt" || true
  grep -iE '\.(map|json|xml|sql|bak|old|config|env)(\?|$)' "$RD/urls/all.txt" >> "$RD/urls/juicy.txt" || true
  sort -u -o "$RD/urls/juicy.txt" "$RD/urls/juicy.txt" 2>/dev/null || true
fi
echo "✅ Juicy URLs (params/admin/api/config): $(wc -l < "$RD/urls/juicy.txt" 2>/dev/null || echo 0)"

# Methodology classification (grep-only, no new tools)
if [ -s "$RD/urls/all.txt" ]; then
  grep -iE '\.js(\?|#|$)' "$RD/urls/all.txt" | grep -ivE '\.json' | sort -u > "$RD/urls/js_urls.txt" || true
  grep -iE '\.(json|xml|graphql|gql)(\?|#|$)|/graphql|/api/v[0-9]' "$RD/urls/all.txt" | sort -u > "$RD/urls/api_urls.txt" || true
  grep -iE 'login|signin|auth|oauth|reset|password|sso' "$RD/urls/all.txt" | sort -u > "$RD/urls/login_flows.txt" || true
  grep -iE 'admin|dashboard|internal|manage|console|panel' "$RD/urls/all.txt" | sort -u > "$RD/urls/admin_panels.txt" || true
  grep -iE 'upload|file|download|media|attachment' "$RD/urls/all.txt" | sort -u > "$RD/urls/file_uploads.txt" || true
  grep -iE '\.(env|bak|backup|old|sql|log|config|cfg|yml|yaml|pem|key|git|htaccess|zip|tar|gz|dump)(\?|#|$)' "$RD/urls/all.txt" | sort -u > "$RD/urls/sensitive_files.txt" || true
  grep -E '=' "$RD/urls/all.txt" | sort -u > "$RD/urls/params.txt" || true
  for f in js_urls api_urls login_flows admin_panels file_uploads sensitive_files params; do
    [ -f "$RD/urls/${f}.txt" ] && [ ! -s "$RD/urls/${f}.txt" ] && rm -f "$RD/urls/${f}.txt" || true
  done
  echo "📁 Classified: js=$(wc -l < "$RD/urls/js_urls.txt" 2>/dev/null || echo 0) api=$(wc -l < "$RD/urls/api_urls.txt" 2>/dev/null || echo 0) admin=$(wc -l < "$RD/urls/admin_panels.txt" 2>/dev/null || echo 0) login=$(wc -l < "$RD/urls/login_flows.txt" 2>/dev/null || echo 0) sensitive=$(wc -l < "$RD/urls/sensitive_files.txt" 2>/dev/null || echo 0) params=$(wc -l < "$RD/urls/params.txt" 2>/dev/null || echo 0)"
fi
echo "📊 URL source breakdown: wayback=$(wc -l < "$RD/urls/wayback.txt" 2>/dev/null || echo 0) js_cdx=$(wc -l < "$RD/urls/wayback_js.txt" 2>/dev/null || echo 0) otx=$(wc -l < "$RD/urls/otx.txt" 2>/dev/null || echo 0) urlscan=$(wc -l < "$RD/urls/urlscan.txt" 2>/dev/null || echo 0) katana=$(wc -l < "$RD/urls/katana.txt" 2>/dev/null || echo 0) html=$(wc -l < "$RD/urls/html_extract.txt" 2>/dev/null || echo 0) all=$(wc -l < "$RD/urls/all.txt" 2>/dev/null || echo 0)"

