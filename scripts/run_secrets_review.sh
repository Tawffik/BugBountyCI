#!/usr/bin/env bash
# RRP-1: generate triage/SECRETS_REVIEW.md from a results root.
# Safe to call with continue-on-error from Zero Track triage phase.
set -euo pipefail

RESULTS_DIR="${1:-${RESULTS_DIR:-.}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -d "$RESULTS_DIR" ]]; then
  echo "[secrets_review] results dir missing: $RESULTS_DIR" >&2
  mkdir -p "$RESULTS_DIR/triage"
  echo "# SECRETS REVIEW

**Status:** \`NO_INPUTS\`

Results directory did not exist at review time.
" > "$RESULTS_DIR/triage/SECRETS_REVIEW.md"
  exit 0
fi

python3 "$SCRIPT_DIR/build_secrets_review.py" --results-dir "$RESULTS_DIR"
echo "[secrets_review] wrote $RESULTS_DIR/triage/SECRETS_REVIEW.md"
