# BugBountyCI — PROJECT STATE

## MODE
FULL RELIABILITY REPAIR CAMPAIGN  
EXIT: CAMPAIGN_COMPLETE | CAMPAIGN_BLOCKED

## VERIFIED
| Item | Evidence |
|------|----------|
| Port discovery | #106–**#109** (29 ports OK) |
| Port ERROR≠EMPTY | #103/#104 |
| Nuclei hostname HTTPS filter | #107–#109 |
| Nuclei light skip pass 2/3 | #108/#109 |
| **Nuclei Tor fallback skip (light)** | **#109** log + step completed ~32m without timeout |
| Nuclei phase PARTIAL in-step | **#109** (not synthesized) |
| High nuclei error on flaky hosts | KNOWN LIMITATION — stays DEGRADED/PARTIAL |

## ACTIVE
| Item | Status |
|------|--------|
| Arjun ERROR≠EMPTY + DIRECT-first | FIXING — verify #110 |

## RUNS
| # | Result |
|---|--------|
| 108 | ports 26; nuclei PARTIAL timeout+Tor burn |
| 109 | ports 29; Tor skip OK; nuclei PARTIAL 52.3% in-step; 67% coverage |
