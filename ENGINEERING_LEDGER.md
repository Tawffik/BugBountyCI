# BugBountyCI Engineering Ledger

## HEAD
Post-#133 honesty + Hunter API seeds (infinite loop cycle).

## LIVE VERIFIED
| Run | Target | SHA | Notes |
|---|---|---|---|
| 37443762040 #133 | capital.com | 8defe15 | tip export index; 32 API; 4 SSRF HIGH_SIGNAL; OOB file empty |
| 37421731026 #129 | nuva.finance | c9c8645 | Smart Fuzz empty honesty; LinkFinder static-only |

## THIS CYCLE (after #133 forensic)
### Gap: SSRF Hunter overstated OOB
- **Symptom:** reason said "OOB callback registered" while `oob_findings.txt` empty
- **Fix:** `96057ca` ssrf_engine probe-fired language; `3b42cb5` hunter annotates OOB_NOT_SEEN / OOB_CONFIRMED from oob_findings
- **Test:** `tests/test_hunter_oob_and_api_seeds.py`

### Gap: LinkFinder API invisible to Hunter
- **Symptom:** capital 32 API_ROUTE only in js_deep/relationships
- **Fix:** `2690fad` load_linkfinder_api_routes → INTERESTING (cap 25)
- **Offline:** 25 seeds from capital normalized file

## CLOSED (prior)
Representation · Historical→Hunter · Smart Fuzz metrics · LinkFinder classify · tip export artifact paths · API-priority JS_TO_ENDPOINT

## NEXT HIGHEST-VALUE GAPS
1. Live verify OOB annotation + API seeds on authorized tip-SHA run (light)
2. Human verify capital SSRF differentials (not auto-confirm)
3. Optional: parameter_intelligence ingest of linkfinder API hosts
4. Sengi when quota returns
