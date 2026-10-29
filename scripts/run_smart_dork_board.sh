#!/usr/bin/env bash
set -euo pipefail
RESULTS_DIR="${1:-.}"
TARGET="${2:-${TARGET:-}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "$TARGET" && -f "$RESULTS_DIR/meta/target.txt" ]]; then
  TARGET=$(head -1 "$RESULTS_DIR/meta/target.txt" | tr -d '\r')
fi
python3 "$SCRIPT_DIR/build_smart_dork_board.py" --results-dir "$RESULTS_DIR" --target "${TARGET:-}"
echo "[smart_dork] wrote $RESULTS_DIR/triage/SMART_DORK_BOARD.md"
