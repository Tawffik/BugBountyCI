#!/usr/bin/env bash
# Cloud Exposure Intelligence V1 — Notion-aligned, bounded, read-only
set -euo pipefail
RD="${1:-results/${TIMESTAMP:-}}"
TARGET="${2:-${TARGET:-}}"
if [ -z "$RD" ] || [ -z "$TARGET" ]; then
  echo "usage: run_cloud_exposure.sh <results_dir> <target>" >&2
  exit 0
fi
mkdir -p "$RD/detection" "$RD/logs" "$RD/meta/phases" "$RD/live"
python3 pipeline/detection/cloud_exposure_engine.py \
  --results-dir "$RD" \
  --target "$TARGET" \
  --max-probes "${CLOUD_EXPOSURE_MAX_PROBES:-12}" \
  2>>"$RD/logs/cloud_exposure.log" || echo "⚠️ cloud_exposure soft-fail — continuing"
if [ -f "$RD/detection/cloud_exposure_summary.json" ]; then
  echo "✅ cloud_exposure summary:"
  head -c 1200 "$RD/detection/cloud_exposure_summary.json" || true
  echo
else
  echo "ℹ️ cloud_exposure produced no summary"
fi
