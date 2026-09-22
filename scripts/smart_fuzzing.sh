#!/usr/bin/env bash
# smart_fuzzing.sh — V1 launcher for the Target-Aware Adaptive Hunter Engine
#
# V1 scope only: Target Profile + Vocabulary + Wolf Selector + Target
# Wordlist + Baseline + (existing) ffuf + Response Diff. No AI, no
# adaptive loop, no exploitation — see docs/PIPELINE_MANIFEST.md and the
# Target-Aware Adaptive Hunter Engine spec for V2/V3.
#
# Usage (called from the "Content Discovery Fuzzing" workflow step):
#   RD=results/<timestamp> TARGET=example.com HUNTING_MODE=normal \
#     scripts/smart_fuzzing.sh
#
# Exit code is always 0 (continue-on-error friendly) — any failure here
# means the caller should fall back to the plain common.txt fuzzing that
# already existed, per the spec's "common wordlist stays fallback" rule.
set -uo pipefail

RD="${RD:?RD (results dir) must be set}"
TARGET="${TARGET:?TARGET must be set}"
MODE="${HUNTING_MODE:-normal}"
UA="${SCAN_USER_AGENT:-Mozilla/5.0}"
USE_TOR="${SMART_FUZZ_USE_TOR:-true}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_DIR="$SCRIPT_DIR/../pipeline/smart-fuzzing"
WOLF_DIR="${WOLF_DIR:-/tmp/wolf}"
OUT_DIR="$RD/smart-fuzzing"

mkdir -p "$OUT_DIR"
FAIL=0

echo "🧠 Smart Fuzzing V1 — target=$TARGET mode=$MODE"

# --- 0. Get Wolf (sparse checkout: DIRS/ + HTTP/ only, per Wolf's own README) ---
if [ ! -d "$WOLF_DIR/DIRS" ]; then
  echo "⬇️ Fetching Wolf knowledge base (DIRS/ + HTTP/ only)..."
  rm -rf "$WOLF_DIR"
  if git clone --filter=blob:none --sparse --depth 1 https://github.com/0xbugatti/wolf.git "$WOLF_DIR" >/dev/null 2>&1; then
    (cd "$WOLF_DIR" && git sparse-checkout set DIRS HTTP >/dev/null 2>&1) || true
  fi
fi
if [ ! -d "$WOLF_DIR/DIRS" ]; then
  echo "⚠️ Wolf checkout failed or unavailable — wolf_selector.py will fall back to app vocabulary only."
fi

# --- 1. Target Profile ---
python3 "$PY_DIR/target_profile.py" --results-dir "$RD" --target "$TARGET" || FAIL=1

# --- 2. Vocabulary Extraction ---
python3 "$PY_DIR/vocabulary.py" --results-dir "$RD" --target "$TARGET" || FAIL=1

# --- 3. Wolf Selector ---
python3 "$PY_DIR/wolf_selector.py" \
  --wolf-dir "$WOLF_DIR" \
  --target-profile "$OUT_DIR/target_profile.json" \
  --mode "$MODE" \
  --results-dir "$RD" || FAIL=1

# --- 4. Target Wordlist Builder ---
python3 "$PY_DIR/wordlist_builder.py" --results-dir "$RD" --mode "$MODE" || FAIL=1

WORDLIST="$OUT_DIR/target_wordlist.txt"
if [ "$FAIL" = "1" ] || [ ! -s "$WORDLIST" ]; then
  echo "⚠️ Smart wordlist build failed or empty — caller should fall back to common.txt."
  exit 0
fi

# --- Host selection (same priority order as the existing fuzzing step) ---
FUZZ_INPUT="$RD/live/expensive_targets.txt"
[ -s "$FUZZ_INPUT" ] || FUZZ_INPUT="$RD/live/scan_order.txt"
[ -s "$FUZZ_INPUT" ] || FUZZ_INPUT="$RD/live/live.txt"
if [ ! -s "$FUZZ_INPUT" ]; then
  echo "⚠️ No live hosts available — nothing to fuzz."
  exit 0
fi

# --- 5. Baseline (SPA-fallback aware, per Intigriti methodology) ---
TOR_FLAG=""
[ "$USE_TOR" = "true" ] && TOR_FLAG="--use-tor"
python3 "$PY_DIR/baseline.py" \
  --results-dir "$RD" \
  --hosts-file "$FUZZ_INPUT" \
  --user-agent "$UA" \
  $TOR_FLAG || true

# --- 6. Controlled Fuzzing (existing ffuf engine, target-specific wordlist) ---
FFUF_JSON_DIR="$OUT_DIR/ffuf_raw"
mkdir -p "$FFUF_JSON_DIR"
mode_budget() { case "$MODE" in light) echo 240;; aggressive) echo 900;; *) echo 500;; esac; }
BUDGET=$(mode_budget)
PER_HOST=45
SECONDS=0
i=0
total=$(wc -l < "$FUZZ_INPUT")
echo "⏱️ Smart fuzzing budget ${BUDGET}s (~${PER_HOST}s/host) across $total host(s)"
while IFS= read -r host; do
  host="$(echo "$host" | tr -d '\r' | xargs)"; [ -z "$host" ] && continue
  if [ "$SECONDS" -ge "$BUDGET" ]; then
    echo "⏱️ Time budget reached after $i/$total host(s)"
    break
  fi
  i=$((i + 1))
  safe_name=$(echo "$host" | sed -E 's#https?://##; s#[^A-Za-z0-9]+#_#g')
  # -s restored after datacamp run 90 diagnostic: Errors ~7-14/300 (low)
  # + exit 0 + some hosts with real results => results=[] is mostly -ac
  # filtering, not TLS death. Keep one-line [ffuf-diag] for future runs.
  RUN_CMD=(ffuf -w "$WORDLIST" -u "${host}/FUZZ" -H "User-Agent: $UA" \
    -mc 200,204,301,302,307,401,403 -fs 0 -ac -t 8 -rate 20 -timeout 8 \
    -of json -o "$FFUF_JSON_DIR/${safe_name}.json" -s)
  ffuf_exit=0
  t_start=$(date +%s)
  if [ "$USE_TOR" = "true" ] && command -v proxychains4 >/dev/null 2>&1; then
    timeout "$PER_HOST" proxychains4 -q "${RUN_CMD[@]}" 2>>"$RD/logs/smart_ffuf.log" || ffuf_exit=$?
  else
    timeout "$PER_HOST" "${RUN_CMD[@]}" 2>>"$RD/logs/smart_ffuf.log" || ffuf_exit=$?
  fi
  t_end=$(date +%s)
  errors_line=$(tail -20 "$RD/logs/smart_ffuf.log" | grep -o "Errors: [0-9]*" | tail -1)
  echo "[ffuf-diag] host=$host exit=$ffuf_exit duration=$((t_end - t_start))s ${errors_line:-Errors:_not_found_in_log}" >> "$RD/logs/smart_ffuf.log"
done < "$FUZZ_INPUT"

# --- 7. Response Diff (baseline-aware classification, not raw status codes) ---
python3 "$PY_DIR/response_diff.py" --results-dir "$RD" --ffuf-json-dir "$FFUF_JSON_DIR" || true

echo "✅ Smart Fuzzing V1 complete — see $OUT_DIR/interesting.txt"
exit 0
