#!/usr/bin/env bash
# Synthetic regression for Port Scan status classification (no real naabu).
# Mirrors the decision rules in zero-track-hunter.yml Port Scanning step.
set -euo pipefail
pass=0
fail=0
assert_eq() {
  local name="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    echo "PASS $name (got=$got)"
    pass=$((pass+1))
  else
    echo "FAIL $name (got=$got want=$want)"
    fail=$((fail+1))
  fi
}

classify() {
  # args: port_n direct_rc tor_rc ftl_flag(0|1)
  local port_n="$1" DIRECT_RC="$2" TOR_RC="$3" _ftl="$4"
  local PORT_SCAN_STATUS
  if [ "${port_n:-0}" -gt 0 ]; then
    PORT_SCAN_STATUS="OK"
  elif [ "$_ftl" -eq 1 ] || [ "${DIRECT_RC:-0}" -ne 0 ] || [ "${TOR_RC:-0}" -ne 0 ]; then
    PORT_SCAN_STATUS="ERROR"
  else
    PORT_SCAN_STATUS="EMPTY"
  fi
  echo "$PORT_SCAN_STATUS"
}

# Test 1: success + ports
assert_eq "T1_ok_ports" "$(classify 5 0 0 0)" "OK"

# Test 2: success + zero ports
assert_eq "T2_empty" "$(classify 0 0 0 0)" "EMPTY"

# Test 3: FTL + zero ports
assert_eq "T3_ftl_error" "$(classify 0 0 0 1)" "ERROR"

# Test 4: timeout (124) + zero ports
assert_eq "T4_timeout_error" "$(classify 0 124 0 0)" "ERROR"
assert_eq "T4b_tor_timeout" "$(classify 0 0 124 0)" "ERROR"

# Test 5: partial ports + later failure still OK (ports preserved)
assert_eq "T5_partial_ok" "$(classify 3 124 1 1)" "OK"

# Test 6: non-zero exit without FTL
assert_eq "T6_nonzero_error" "$(classify 0 1 1 0)" "ERROR"

# Dedicated log isolation: shared log FTL must NOT drive status when portscan log clean
# (simulated by only passing _ftl from portscan log, not shared)
assert_eq "T7_shared_log_ignored" "$(classify 0 0 0 0)" "EMPTY"

echo "---"
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
