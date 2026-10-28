#!/usr/bin/env bash
set -euo pipefail
RESULTS_DIR="${1:-${RESULTS_DIR:-.}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$RESULTS_DIR/triage" "$RESULTS_DIR/meta"
python3 "$SCRIPT_DIR/build_quality_gate.py" --results-dir "$RESULTS_DIR"
echo "[quality_gate] wrote $RESULTS_DIR/triage/QUALITY_GATE.md"
