# BugBountyCI Engineering Ledger

## HEAD
Latest `main` (FFUF calibration observability after false-OK fix).

## Representation Differential — CLOSED / PROVEN
#128 · 6c702aa · 7 pairs · 5 NO_DIFFERENTIAL · 2 NETWORK_ERROR

## Smart Fuzzing — IN PROGRESS (P0 + observability offline)

### Proven offline on #128 artifacts
- wordlist_entries = **70**
- hosts_fuzzed = **7**
- planned_requests_ceiling = **490**
- post_calibration_match_count = **0**
- autocalibration_enabled = **true**
- pipeline_state = **REQUESTS_EXECUTED_NO_MATCH**
- finding_count = **0** (headers are not findings)

### Interpretation
FFUF **did run** against a non-empty wordlist. Zero `results[]` means **no post-`-ac` matches**, not "phase skipped" and not "0 HTTP requests".

### Changes
1. False interesting-count / phase OK from header lines — fixed
2. metrics.json + pipeline_state taxonomy — fixed
3. planned_requests_ceiling vs post_calibration_match_count — added
4. wordlist_size.txt from smart_fuzzing.sh — added
5. `-ac` **retained** (no blind removal)

### Live
Not run yet. One verification run justified after this lands on main.

### Next
1. Optional: single live verify metrics/phase semantics
2. LinkFinder normalization
3. Nuclei track separation
4. Sengi when quota returns
