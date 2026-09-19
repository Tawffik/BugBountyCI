#!/usr/bin/env bash
# run_open_redirect.sh — wires OpenRedirectEngine into the pipeline.
# Same conventions as run_access_control.sh: env-var driven,
# continue-on-error, always exits 0 (new/unproven layer, must never
# affect the rest of the run).
set -uo pipefail

RD="${RD:?RD (results dir) must be set}"
TARGET="${TARGET:-}"
UA="${SCAN_USER_AGENT:-Mozilla/5.0}"
USE_TOR="${OPEN_REDIRECT_USE_TOR:-true}"

TOR_FLAG=""
[ "$USE_TOR" = "true" ] && TOR_FLAG="--use-tor"

python3 pipeline/detection/run_open_redirect.py \
  --results-dir "$RD" \
  --target "$TARGET" \
  --user-agent "$UA" \
  $TOR_FLAG \
  --timeout 10 \
  --max-candidates 60 || echo "⚠️ Open Redirect Engine failed — continuing, this does not affect the rest of the run"

exit 0
