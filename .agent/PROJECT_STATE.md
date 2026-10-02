# BugBountyCI — PROJECT STATE

## MODE
FULL RELIABILITY + SYSTEM EVOLUTION CAMPAIGN  
EXIT: CAMPAIGN_COMPLETE | CAMPAIGN_BLOCKED

## HEAD
See main tip.

## RELIABILITY FOUNDATION (Phase 1)

| Item | Status | Evidence |
|------|--------|----------|
| Port discovery | LIVE VERIFIED | #106–#110 |
| Port ERROR≠EMPTY | LIVE VERIFIED | #103/#104 |
| Nuclei hostname/HTTPS filter | LIVE VERIFIED | #107–#110 |
| Nuclei light Tor gate | LIVE VERIFIED | #109/#110 |
| Nuclei PARTIAL semantics | LIVE VERIFIED | #108–#110 |
| Arjun ERROR≠EMPTY / PARTIAL | LIVE VERIFIED | **#110** phase+health flag |
| High nuclei error flaky hosts | KNOWN LIMITATION | stays DEGRADED/PARTIAL |
| Arjun upstream AttributeError | KNOWN LIMITATION | PARTIAL not clean |

## ADDITIVE EXPORT (Phase 2 start)
| Artifact | Purpose |
|----------|---------|
| meta/engine_health.json | all phases + overall + flags |
| meta/target_profile.json | counts + phase_summary |

## RUNS
| # | SHA | Notes |
|---|-----|-------|
| 109 | 8e237ee | Tor gate OK |
| 110 | 987d88c | Arjun PARTIAL verified; ports 15; nuclei PARTIAL 51.8% |
| 111 | pending | export + regression check |

## NEXT (dependency order)
1. Live-verify engine_health + target_profile export
2. Normalize more engines to phase files (corsy, dalfox) where silent
3. Target/surface model enrichment (hosts.jsonl) without rewrite
4. Do NOT claim CAMPAIGN_COMPLETE until observation+health contracts hold E2E

## BOUNDARY
BugBountyCI = recon/observation producer only. No SRA merge.
