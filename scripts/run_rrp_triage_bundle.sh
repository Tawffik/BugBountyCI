#!/usr/bin/env bash
# Run all RRP operator surfaces that exist in this checkout.
# Safe: continue on missing sibling scripts (partial merges).
set -euo pipefail
RESULTS_DIR="${1:-${RESULTS_DIR:-.}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$RESULTS_DIR/triage" "$RESULTS_DIR/meta"

run_if() {
  local sh="$1"
  if [[ -f "$SCRIPT_DIR/$sh" ]]; then
    bash "$SCRIPT_DIR/$sh" "$RESULTS_DIR" || echo "[rrp] $sh non-zero (ignored)"
  else
    echo "[rrp] skip missing $sh"
  fi
}

run_if run_funnel_gate.sh
run_if run_secrets_review.sh
run_if run_exposure_queue.sh
run_if run_disclosure_desk.sh
echo "[rrp] triage bundle done under $RESULTS_DIR/triage"
