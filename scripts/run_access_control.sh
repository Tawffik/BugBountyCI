#!/usr/bin/env bash
# run_access_control.sh — wires AccessControlEngine (pipeline/detection/)
# into the actual pipeline for the first time. Everything before this was
# tested in isolation only.
#
# Reads <RD>/smart-fuzzing/response_diffs.json (produced by the existing
# Content Discovery Fuzzing step) — if that file doesn't exist yet, the
# engine's own prerequisites() check skips cleanly (see engine_results.json
# for "prerequisites not met"), so this is safe to call unconditionally.
#
# Exit code is always 0 — this is a NEW, unproven intelligence layer, so a
# failure here must never affect the rest of the run. Same continue-on-error
# philosophy as scripts/smart_fuzzing.sh.
set -uo pipefail

RD="${RD:?RD (results dir) must be set}"
TARGET="${TARGET:-}"
UA="${SCAN_USER_AGENT:-Mozilla/5.0}"
USE_TOR="${ACCESS_CONTROL_USE_TOR:-true}"

TOR_FLAG=""
[ "$USE_TOR" = "true" ] && TOR_FLAG="--use-tor"

python3 pipeline/detection/run_access_control.py \
  --results-dir "$RD" \
  --target "$TARGET" \
  --user-agent "$UA" \
  $TOR_FLAG \
  --timeout 10 \
  --max-endpoints 30 || echo "⚠️ Access-Control Engine failed — continuing, this does not affect the rest of the run"

exit 0
