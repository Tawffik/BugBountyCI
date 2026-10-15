"""smart_fuzzing.sh must not map FFUF_PARSE_FAILURE to phase empty."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_parse_failure_maps_to_error_phase():
    src = (ROOT / "scripts" / "smart_fuzzing.sh").read_text(encoding="utf-8")
    assert "FFUF_PARSE_FAILURE" in src
    assert "PARTIAL_FFUF_PARSE" in src
    # error branch before empty branch for parse states
    err_pos = src.find('write_phase_status "$RD" "smart_fuzzing" "error" "state=${pipeline_state}')
    empty_pos = src.find('write_phase_status "$RD" "smart_fuzzing" "empty"')
    assert err_pos > 0 and empty_pos > 0
    assert err_pos < empty_pos
