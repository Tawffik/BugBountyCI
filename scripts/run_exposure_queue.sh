#!/usr/bin/env bash
set -euo pipefail
RESULTS_DIR="${1:-${RESULTS_DIR:-.}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$RESULTS_DIR/triage"
python3 "$SCRIPT_DIR/build_exposure_queue.py" --results-dir "$RESULTS_DIR"
echo "[exposure_queue] wrote $RESULTS_DIR/triage/EXPOSURE_QUEUE.md"
