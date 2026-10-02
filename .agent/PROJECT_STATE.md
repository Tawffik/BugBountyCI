# BugBountyCI — PROJECT STATE

## MODE
FULL AUTONOMOUS CAMPAIGN V3  
EXIT only: CAMPAIGN_COMPLETE | CAMPAIGN_BLOCKED

## VERIFIED
| Item | Evidence |
|------|----------|
| Port discovery / ERROR≠EMPTY | #106–#111 |
| Nuclei filter / Tor gate / PARTIAL | #109–#111 |
| Arjun PARTIAL + Health warning | #110–#111 |
| **Export engine_health.json** | **#111 LIVE VERIFIED** |
| **Export target_profile.json** | **#111 LIVE VERIFIED** |

## LIMITATIONS (honest)
| Item | Representation |
|------|----------------|
| Nuclei ~52% flaky-host errors | PARTIAL + DEGRADED |
| Arjun upstream AttributeError | PARTIAL not clean |

## IN PROGRESS
| Item | Status |
|------|--------|
| hosts.jsonl (Phase 3 surface model) | CODE — verify #112 |
| Phase 2 full observation.jsonl | next after hosts |
| Vocabulary / response intel / adaptive SF | later dependencies |

## RUNS
| # | Result |
|---|--------|
| 110 | Arjun PARTIAL verified |
| 111 | **export LIVE VERIFIED**; ports 25; arjun PARTIAL; nuclei PARTIAL 51.9% |
| 112 | pending hosts.jsonl |

## BOUNDARY
Recon/observation producer only. No SRA merge.
