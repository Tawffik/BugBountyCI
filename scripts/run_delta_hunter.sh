#!/usr/bin/env bash
set -euo pipefail
RESULTS_DIR="${1:-${RESULTS_DIR:-.}}"
PREV_DIR="${2:-${PREV_RESULTS_DIR:-}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$RESULTS_DIR/triage" "$RESULTS_DIR/meta"
if [[ -n "${PREV_DIR}" ]]; then
  python3 "$SCRIPT_DIR/build_delta_hunter.py" --results-dir "$RESULTS_DIR" --prev-dir "$PREV_DIR"
else
  python3 "$SCRIPT_DIR/build_delta_hunter.py" --results-dir "$RESULTS_DIR"
fi
echo "[delta] wrote $RESULTS_DIR/triage/DELTA.md"
