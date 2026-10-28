#!/usr/bin/env bash
set -euo pipefail
RESULTS_DIR="${1:-${RESULTS_DIR:-.}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/build_opportunity_board.py" --results-dir "$RESULTS_DIR"
echo "[opportunity] wrote $RESULTS_DIR/triage/OPPORTUNITY.md"
