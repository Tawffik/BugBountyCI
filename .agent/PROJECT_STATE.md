# BugBountyCI — PROJECT STATE

## ACTIVE MODE
FULL RELIABILITY REPAIR CAMPAIGN  
EXIT only: CAMPAIGN_COMPLETE | CAMPAIGN_BLOCKED

## HEAD
See latest main.

## VERIFIED
| Item | Evidence |
|------|----------|
| Port discovery | #106, #107, **#108** (26 ports, OK) |
| Port ERROR≠EMPTY | #103/#104 |
| Nuclei hostname HTTPS filter | #107/#108 |
| Nuclei phase PARTIAL after timeout | **#108** synthesized |
| Light skip pass 2/3 | #108 logs |

## OPEN / IN PROGRESS
| Item | Notes |
|------|-------|
| Nuclei Tor fallback budget burn | **FIXED** — live verify #109 |
| Nuclei high error on flaky hosts | KNOWN LIMITATION when PARTIAL/DEGRADED surfaced |
| Arjun AttributeError mid-run | investigate if ERROR silent |
| Info disclosure / API Discovery step timeouts | observe |

## RUNS
| # | SHA | Class |
|---|-----|-------|
| 106 | 963ba62 | ports VERIFIED; nuclei 41% |
| 107 | 9739fd7 | ports 22; nuclei 53% filter OK |
| 108 | 7279d32 | ports 26; nuclei PARTIAL 52%; health synth OK |
| 109 | pending | Tor-gate verify |
