#!/usr/bin/env bash
set -euo pipefail
RESULTS_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/build_easy_wins.py" --results-dir "$RESULTS_DIR"
echo "[easy_wins] wrote $RESULTS_DIR/triage/EASY_WINS.md"
