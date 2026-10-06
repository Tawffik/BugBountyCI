# BugBountyCI Engineering Ledger

## HEAD
See latest `main` (smart-fuzzing metrics fix after `ae0f721`).

## Representation Differential — CLOSED / PROVEN
Live `#128` / `37408543776` · SHA `6c702aa` · 7 candidates · 5 NO_DIFFERENTIAL · 2 NETWORK_ERROR · Hunter rep=0.

## Smart Fuzzing — IN PROGRESS (offline P0 fixed)

### Audit findings (#128 artifacts)
1. `interesting.txt` contained **only header comments** (5 lines).
2. Phase status was **`ok` with `interesting_lines=5`** — FALSE SUCCESS (headers counted as findings).
3. All `ffuf_raw/*.json` had **`results: []`** with **`autocalibration: true`** → upstream starvation of response_diff (not a response_diff bug).
4. `response_diffs.json = []` and empty clusters are **correct** given zero ffuf matches.
5. Baseline present for hosts; SPA/redirect baselines observed.

### Root cause
Phase status used `safe_count(interesting.txt)` (physical lines including `#` headers).
FFUF `-ac` left zero post-calibration matches on this target/run (documented; not removed blindly).

### Changes
- `response_diff.py`: `finding_count`, `aggregate_ffuf_raw`, `metrics.json`, `pipeline_state` taxonomy (`REQUESTS_EXECUTED_NO_MATCH`, etc.)
- `smart_fuzzing.sh`: phase status from `metrics.json`
- `fallback_gate.py`: if status=ok but metrics finding_count=0 → treat as empty_valid
- tests: header≠finding, ffuf states, fallback guard

### Offline verification
Replay on #128 ffuf_raw → `pipeline_state=REQUESTS_EXECUTED_NO_MATCH`, `finding_count=0`, `raw_match_count=0`.

### Live verification
**Not launched** (offline-first gate). Next single live run only after remaining calibration observability is accepted.

### Known limitations
- `-ac` may filter all matches on catch-all/SPA hosts; need request-count evidence from ffuf logs for deeper calibration contract (future).
- response_clusters remain empty until raw matches exist.

### Next highest-value gap
1. FFUF calibration observability (requests attempted vs post-ac matches) without removing `-ac` blindly.
2. LinkFinder normalization (chunk.js noise).
3. Nuclei track separation.
