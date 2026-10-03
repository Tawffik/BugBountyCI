# BugBountyCI — PROJECT STATE

## MODE
FULL AUTONOMOUS ENGINEERING CAMPAIGN V4 — IN PROGRESS  
EXIT: CAMPAIGN_COMPLETE | CAMPAIGN_BLOCKED only

## HEAD
See main tip (surface model urls/endpoints/parameters pending live verify)

## VERIFIED CONTRACTS
| Contract | Evidence |
|----------|----------|
| Port discovery / ERROR≠EMPTY | #106–#112 |
| Nuclei filter/Tor/PARTIAL | #109–#112 |
| Arjun PARTIAL + health | #110 |
| engine_health + target_profile | #111 |
| hosts.jsonl | #112 |
| write_pipeline_exports extraction | a1bcb54 (await #114) |

## IN PROGRESS
| Item | Status |
|------|--------|
| #114 | live verify exports script + observations |
| urls.jsonl + endpoints.jsonl + parameters.jsonl | CODE ready — live verify after #114 |

## KNOWN LIMITATIONS
| Item | Representation |
|------|----------------|
| Nuclei ~50% flaky hosts | PARTIAL / DEGRADED |
| Arjun AttributeError upstream | PARTIAL |

## NEXT DEPENDENCY AFTER LIVE VERIFY
1. Harvest #114
2. Dispatch run for urls/endpoints/parameters export
3. Application vocabulary (smart-fuzzing/vocabulary + meta export)
4. Response intelligence enrichment
5. Continue roadmap — never stop at phase boundary

## BOUNDARY
BugBountyCI = recon producer only. No SRA merge.
