# BugBountyCI — PROJECT STATE

## 1. Identity
| Field | Value |
|-------|--------|
| Repo | Tawffik/BugBountyCI |
| Branch | main |
| **HEAD** | pending post-nuclei-fix commit |

## 2. ACTIVE MODE
```
FULL RELIABILITY REPAIR CAMPAIGN
ONE change at a time → test → run → harvest → next root cause
EXIT: CAMPAIGN_COMPLETE | CAMPAIGN_BLOCKED
```
Single-ticket STOP rule is **retired**.

## 3. Verified this campaign
| Item | Evidence |
|------|----------|
| Port ERROR≠EMPTY | #103/#104 |
| Port health flag | #104 |
| Port **discovery** | **#106** — 8 IPs, **14 ports**, phase **OK**, health OK |
| GA expression limit | #105 → scripts/port_scan.sh |

## 4. Active
| Item | Status |
|------|--------|
| Nuclei input quality / error rate | FIX committed — live verify next |
| Health contract (other stages) | OPEN |
| Provenance redesign | DEFER |

## 5. Runs
| # | SHA | Class |
|---|-----|-------|
| 104 | 413a93c | DEGRADED (ports ERROR) |
| 105 | ef143ac | UNUSABLE |
| 106 | 963ba62 | **DEGRADED** but ports **VERIFIED**; Nuclei 41.6% errors |

## 6. Boundary
Recon only. No SRA merge / new engines / LLM infra.
