"""Gap D — common.txt fallback gate for Content Discovery Fuzzing.

Bug #16 made smart_fuzzing.sh write meta/phases/smart_fuzzing.json with
status ok|empty|error|…. The Content Discovery step still treated
"discovered.txt empty" alone as reason to run SecLists common.txt,
undoing EMPTY_VALID smart-fuzzing runs.

This module is the single decision function. The workflow must call it
instead of only checking that discovered.txt is non-empty.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional, Tuple, Union

# Status values written by scripts/pipeline_lib.sh write_phase_status
# and scripts/smart_fuzzing.sh (do not invent a parallel vocabulary).
STATUS_EMPTY = "empty"  # EMPTY_VALID: ran, zero interesting observations
STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"
STATUS_SKIPPED_STARVED = "skipped_starved"
STATUS_CANCELLED = "cancelled"

PathLike = Union[str, Path]


def load_phase_status(path: Optional[PathLike]) -> Tuple[Optional[dict], str]:
    """Load phase JSON. Returns (data|None, kind).

    kind is one of:
      present — valid JSON object loaded
      missing — path absent or None
      malformed — unreadable or not a JSON object
    """
    if path is None:
        return None, "missing"
    p = Path(path)
    if not p.is_file():
        return None, "missing"
    try:
        raw = p.read_text(encoding="utf-8", errors="replace").strip()
        if not raw:
            return None, "malformed"
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None, "malformed"
        return data, "present"
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None, "malformed"



def load_smart_fuzzing_metrics(results_dir: Optional[PathLike] = None) -> Optional[dict]:
    """Load smart-fuzzing/metrics.json if present (structured finding_count)."""
    if not results_dir:
        return None
    path = Path(results_dir) / "smart-fuzzing" / "metrics.json"
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None


def should_run_common_txt_fallback(
    phase_status_path: Optional[PathLike] = None,
    *,
    phase_data: Optional[dict] = None,
) -> Tuple[bool, str]:
    """Decide whether Content Discovery may fall back to common.txt.

    Returns (should_run_fallback, reason_code).

    EMPTY_VALID (status == \"empty\"):
        Smart fuzzing ran successfully and found nothing interesting.
        Do NOT run common.txt — that would undo target-aware selection.

    status == \"ok\":
        Smart fuzzing reported success with interesting lines. If
        discovered.txt is still empty, that is a transfer/grep issue,
        not a signal to replace the smart wordlist with SecLists.

    status == \"error\" | skipped* | cancelled:
        Engine failed or did not complete target-aware path → fallback
        allowed so the step does not hard-regress to zero surface.

    Missing or malformed phase file:
        Cannot prove EMPTY_VALID. Allow fallback (safe failure semantics:
        prefer recovery over silent under-coverage). Never treat missing
        status as ZERO_FINDING / successful empty.
    """
    if phase_data is None:
        phase_data, kind = load_phase_status(phase_status_path)
        if kind == "missing":
            return True, "missing_phase_status"
        if kind == "malformed":
            return True, "malformed_phase_status"
    assert phase_data is not None

    status = str(phase_data.get("status") or "").strip().lower()

    if status == STATUS_EMPTY:
        return False, "empty_valid"
    if status == STATUS_OK:
        # Guard: phase file may say ok from legacy header-line counts.
        # Prefer metrics.json finding_count when available.
        metrics = None
        # Infer results dir from phase path when possible
        if phase_status_path:
            try:
                p = Path(phase_status_path)
                # .../meta/phases/smart_fuzzing.json → results root is parents[2]
                if p.name.endswith(".json") and p.parent.name == "phases":
                    metrics = load_smart_fuzzing_metrics(p.parent.parent.parent)
            except Exception:
                metrics = None
        if metrics is not None:
            fc = int(metrics.get("finding_count") or 0)
            if fc == 0:
                return False, "empty_valid_metrics_zero_findings"
        return False, "ok"
    if status == STATUS_ERROR:
        return True, "error"
    if status in (STATUS_SKIPPED, STATUS_SKIPPED_STARVED, STATUS_CANCELLED):
        return True, status
    if not status:
        return True, "missing_status_field"
    return True, f"unknown_status:{status}"


def main(argv: Optional[list] = None) -> int:
    """CLI for the workflow: exit 0 = run fallback, exit 1 = skip fallback.

    Usage:
      python3 pipeline/smart-fuzzing/fallback_gate.py "$RD/meta/phases/smart_fuzzing.json"
    Prints reason_code to stdout for logs.
    """
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    path = args[0] if args else None
    run, reason = should_run_common_txt_fallback(path)
    print(reason)
    return 0 if run else 1


if __name__ == "__main__":
    raise SystemExit(main())
