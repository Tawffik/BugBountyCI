#!/usr/bin/env bash
# P0: generate triage/DISCLOSURE_DESK.md from existing artifacts.
set -euo pipefail
RESULTS_DIR="${1:-${RESULTS_DIR:-.}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$RESULTS_DIR/triage" "$RESULTS_DIR/meta"
python3 "$SCRIPT_DIR/build_disclosure_desk.py" --results-dir "$RESULTS_DIR"
