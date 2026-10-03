# BugBountyCI — PROJECT STATE

## MODE
FULL AUTONOMOUS ENGINEERING CAMPAIGN V4 — IN PROGRESS  
EXIT: CAMPAIGN_COMPLETE | CAMPAIGN_BLOCKED only

## HEAD
See main tip

## LIVE VERIFIED CONTRACTS
| Contract | Evidence |
|----------|----------|
| Port / ERROR≠EMPTY | #106–#114 |
| Nuclei filter/Tor/PARTIAL | #109–#114 |
| Arjun PARTIAL + health | #110/#114 |
| engine_health + target_profile | #111/#114 |
| hosts.jsonl | #112/#114 (18 hosts) |
| **observations.jsonl** | **#114** (12 obs, schema v1) |
| write_pipeline_exports script | #114 success (no GA 21k fail) |

## CODE READY — PENDING LIVE ON TIP
| Item | Commit |
|------|--------|
| urls/endpoints/parameters jsonl | 376c1d6 |
| vocabulary + relationships | d6bfa60 |
| response_clusters | 6b41c86 |

## ACTIVE
| Run | SHA | Purpose |
|-----|-----|---------|
| #115 | 92e1885 | surface+vocab (in progress) |
| #116 | tip | full export incl response_clusters |

## KNOWN LIMITATIONS
Nuclei ~54% flaky hosts → PARTIAL; Arjun AttributeError → PARTIAL

## NEXT AFTER #115/#116 HARVEST
1. Confirm urls/endpoints/parameters/vocabulary/relationships/response_clusters live
2. Strengthen response intelligence export coverage
3. Hunter queue structured from observations
4. Continue roadmap — never stop at phase boundary

## BOUNDARY
BugBountyCI = recon producer. No SRA merge.
