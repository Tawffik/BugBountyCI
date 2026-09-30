"""Gap D tests: common.txt fallback must honor meta/phases/smart_fuzzing.json.

Run with:
  python3 -m pytest pipeline/smart-fuzzing/tests/test_fallback_gate.py -q
or:
  python3 pipeline/smart-fuzzing/tests/test_fallback_gate.py
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
SMART_FUZZING_DIR = os.path.dirname(HERE)
if SMART_FUZZING_DIR not in sys.path:
    sys.path.insert(0, SMART_FUZZING_DIR)

from fallback_gate import (  # noqa: E402
    load_phase_status,
    main as gate_main,
    should_run_common_txt_fallback,
)


def _write_phase(tmp_path: Path, status: str, detail: str = "") -> Path:
    p = tmp_path / "smart_fuzzing.json"
    p.write_text(
        json.dumps(
            {
                "phase": "smart_fuzzing",
                "status": status,
                "detail": detail,
                "ts": "2026-09-30T00:00:00Z",
                "network_mode": "direct_then_tor",
            }
        ),
        encoding="utf-8",
    )
    return p


def test_empty_valid_does_not_trigger_fallback(tmp_path: Path) -> None:
    path = _write_phase(tmp_path, "empty", "ran to completion, 0 interesting")
    run, reason = should_run_common_txt_fallback(path)
    assert run is False
    assert reason == "empty_valid"


def test_empty_valid_via_phase_data() -> None:
    run, reason = should_run_common_txt_fallback(
        phase_data={"phase": "smart_fuzzing", "status": "empty"}
    )
    assert run is False
    assert reason == "empty_valid"


def test_error_allows_fallback(tmp_path: Path) -> None:
    path = _write_phase(tmp_path, "error", "vocabulary crashed")
    run, reason = should_run_common_txt_fallback(path)
    assert run is True
    assert reason == "error"


def test_skipped_allows_fallback(tmp_path: Path) -> None:
    path = _write_phase(tmp_path, "skipped", "not executed")
    run, reason = should_run_common_txt_fallback(path)
    assert run is True
    assert reason == "skipped"


def test_skipped_starved_allows_fallback(tmp_path: Path) -> None:
    path = _write_phase(tmp_path, "skipped_starved")
    run, reason = should_run_common_txt_fallback(path)
    assert run is True
    assert reason == "skipped_starved"


def test_missing_phase_allows_fallback_not_zero_finding(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.json"
    run, reason = should_run_common_txt_fallback(missing)
    assert run is True
    assert reason == "missing_phase_status"
    assert reason != "empty_valid"


def test_none_path_allows_fallback() -> None:
    run, reason = should_run_common_txt_fallback(None)
    assert run is True
    assert reason == "missing_phase_status"


def test_malformed_json_allows_fallback(tmp_path: Path) -> None:
    p = tmp_path / "smart_fuzzing.json"
    p.write_text("{not-json", encoding="utf-8")
    run, reason = should_run_common_txt_fallback(p)
    assert run is True
    assert reason == "malformed_phase_status"


def test_empty_file_malformed(tmp_path: Path) -> None:
    p = tmp_path / "smart_fuzzing.json"
    p.write_text("", encoding="utf-8")
    run, reason = should_run_common_txt_fallback(p)
    assert run is True
    assert reason == "malformed_phase_status"


def test_non_object_json_malformed(tmp_path: Path) -> None:
    p = tmp_path / "smart_fuzzing.json"
    p.write_text('["empty"]', encoding="utf-8")
    data, kind = load_phase_status(p)
    assert data is None
    assert kind == "malformed"


def test_ok_does_not_trigger_fallback(tmp_path: Path) -> None:
    path = _write_phase(tmp_path, "ok", "interesting_lines=3")
    run, reason = should_run_common_txt_fallback(path)
    assert run is False
    assert reason == "ok"


def test_cli_exit_codes(tmp_path: Path) -> None:
    empty = _write_phase(tmp_path, "empty")
    assert gate_main([str(empty)]) == 1  # skip fallback
    err = _write_phase(tmp_path, "error")
    assert gate_main([str(err)]) == 0  # run fallback


if __name__ == "__main__":
    import tempfile

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        checks = [
            ("empty_valid", lambda: test_empty_valid_does_not_trigger_fallback(t)),
            ("error", lambda: test_error_allows_fallback(t)),
            ("skipped", lambda: test_skipped_allows_fallback(t)),
            ("missing", lambda: test_missing_phase_allows_fallback_not_zero_finding(t)),
            ("malformed", lambda: test_malformed_json_allows_fallback(t)),
            ("ok", lambda: test_ok_does_not_trigger_fallback(t)),
            ("cli", lambda: test_cli_exit_codes(t)),
        ]
        for name, fn in checks:
            try:
                fn()
                print(f"  ✅ {name}")
            except Exception as e:
                failures += 1
                print(f"  ❌ {name}: {e}")
    raise SystemExit(failures)
