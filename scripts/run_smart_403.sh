#!/usr/bin/env bash
# run_smart_403.sh — Bounded adaptive 403/401 phase (Notion Smart 403 Framework)
# Placement: AFTER Access-Control Intelligence (needs blocked endpoint candidates).
# Never fails the pipeline.
set -uo pipefail
# Accept optional args: <results_dir> [target]
if [ -n "${1:-}" ]; then
  RD="$1"
fi
RD="${RD:-results/${TIMESTAMP:-}}"
TARGET="${2:-${TARGET:-}}"
UA="${SCAN_USER_AGENT:-Mozilla/5.0}"
MAX="${SMART_403_MAX_ENDPOINTS:-12}"

if [ -z "$RD" ] || [ "$RD" = "results/" ]; then
  echo "⚠️ smart_403: RD unset — skip" >&2
  exit 0
fi
mkdir -p "$RD/logs" "$RD/detection" "$RD/meta/phases"

python3 pipeline/detection/smart_403_engine.py \
  --results-dir "$RD" \
  --target "$TARGET" \
  --user-agent "$UA" \
  --max-endpoints "$MAX" \
  --timeout 8 \
  2>>"$RD/logs/smart_403.log" || echo "⚠️ smart_403 phase failed — continuing"

exit 0
