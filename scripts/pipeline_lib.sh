#!/usr/bin/env bash
# Shared helpers for BugBountyCI — source from other scripts.
# NETWORK_MODE: direct | direct_then_tor
# USE_TOR: true|false — allows Tor fallback when mode is direct_then_tor

safe_count() {
  local f="$1"
  if [ -f "$f" ]; then
    wc -l < "$f" 2>/dev/null | tr -d ' ' || echo 0
  else
    echo 0
  fi
}

write_phase_status() {
  # write_phase_status <results_dir> <phase> <status> [detail]
  # status: ok | empty | error | skipped_starved | skipped | cancelled
  local rd="$1" phase="$2" status="$3" detail="${4:-}"
  mkdir -p "$rd/meta/phases"
  local out="$rd/meta/phases/${phase}.json"
  local ts
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)
  printf '{"phase":"%s","status":"%s","detail":%s,"ts":"%s","network_mode":"%s"}\n' \
    "$phase" "$status" \
    "$(printf '%s' "$detail" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo "\"$detail\"")" \
    "$ts" \
    "${NETWORK_MODE:-unknown}" \
    > "$out" 2>/dev/null || echo "{\"phase\":\"$phase\",\"status\":\"$status\"}" > "$out"
}

# Returns 0 if Tor fallback is allowed for this job
tor_fallback_allowed() {
  [ "${USE_TOR:-false}" = "true" ] || return 1
  case "${NETWORK_MODE:-direct_then_tor}" in
    direct) return 1 ;;
    direct_then_tor|tor_then_direct|*) return 0 ;;
  esac
}
