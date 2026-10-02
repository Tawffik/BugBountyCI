# BugBountyCI — PROJECT STATE

> CURRENT operational state for agents.
> Reconcile with repository + run evidence before any code change.

## 1. Identity

| Field | Value |
|-------|--------|
| Repository | `Tawffik/BugBountyCI` |
| Branch | `main` |
| **HEAD** | **`85b9905`** (state); port code tip **`963ba62`** |

## 2. ACTIVE MODE (authoritative)

```
ACTIVE MODE: FULL RELIABILITY REPAIR CAMPAIGN

IMPLEMENTATION RULE:
  ONE root-cause code change at a time
  → test → commit → real Zero Track → harvest → whole-pipeline analysis

CAMPAIGN RULE:
  Do NOT stop after a single problem is closed.
  Do NOT stop after a single green workflow.
  After each verified cycle, select the next evidence-backed reliability root cause.

EXIT ONLY:
  CAMPAIGN_COMPLETE  |  CAMPAIGN_BLOCKED
```

**Retired (historical only):** "After active problem closed → STOP" and "one active priority for the whole project" from older ticket-by-ticket workflow. Those applied to single-ticket repair; they do **not** govern this campaign. Historical repair notes remain in the Ledger for reference.

## 3. Source of truth

1. Current repository code  
2. Current GitHub Actions runs / artifacts  
3. This file  
4. `docs/ENGINEERING_LEDGER.md`  
5. Notion Fix Control Center (if reachable)  
6. Master Architecture  
7. Older chat  

## 4. Campaign board (current)

| Area | Status | Evidence | Required action |
|------|--------|----------|-----------------|
| Port classification ERROR≠EMPTY | LIVE VERIFIED | #103/#104 | protect |
| Port health flag | LIVE VERIFIED | #104 | protect |
| Port **discovery** | VERIFYING | #106 in progress on 963ba62 | harvest #106 |
| YAML expression limit | FIXED | #105 UNUSABLE → 963ba62 script extract | protect |
| DNS discovery honesty | FIXED (historical dig fallback) | ledger | protect |
| Health contract (pipeline-wide) | OPEN | audit | after ports settled |
| Nuclei ~44% errors | OPEN | #104 | after ports |
| Arjun/Corsy zeros | OPEN / may be valid empty | #104 | explain after harvest |
| Smart Fuzz Gap D | REFERENCE | 46fc0a6 | protect unless regression |
| Gap I param intel | REFERENCE | 5497171 | protect unless regression |
| Provenance | DEFER | audit | no redesign without proof |
| Response intelligence | DEFER | ledger E/F | later |

## 5. Run history

| Run | SHA | Class | Notes |
|-----|-----|-------|-------|
| #104 | 413a93c | DEGRADED / TRUTHFUL FAILURE | ports ERROR, FTL, health OK for ports |
| #105 | ef143ac | UNUSABLE | GA expression length |
| #106 | 963ba62 | in progress | dig/getent/connect + port_scan.sh |

## 6. Architectural boundary

BugBountyCI = Recon / Discovery / Observation only. Not security-research-agent. No new engines/LLM/DB in this campaign.

## 7. Principle

truthful observation > impressive output · root cause > symptom · known limitation > fake success
