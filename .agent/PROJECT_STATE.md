# BugBountyCI — PROJECT STATE

> Canonical operational state for implementation agents.
> CURRENT STATE only — reconcile with repo + run evidence before code changes.

## 1. Identity

| Field | Value |
|-------|--------|
| Repository | `Tawffik/BugBountyCI` |
| Default branch | `main` |
| **Current HEAD** | **`cd536a1`** (`fix(ports): dnsx IP pre-resolve + no-cdn retry; health surfaces port_scan ERROR`) |
| Port-scan lineage | `28dd077` → `1491f1f` → `cd536a1` |
| Last reconciliation | 2026-10-02 final repair pass |

## 2. Source of Truth

1. Current repository code  
2. Current run artifacts/logs  
3. This file  
4. Notion Fix Control Center  
5. `docs/ENGINEERING_LEDGER.md`  
6. Master Architecture  
7. Older notes/chat  

## 3. CURRENT ACTIVE WORK

| Field | Value |
|-------|--------|
| Active Gate | **P0 — Zero Track Reliability (final repair)** |
| Active Problem | **Port Scan discovery** (classification OK on #103; discovery FTL) |
| Status | **VERIFYING** — `cd536a1` not live-verified yet |

### Evidence #103 (`28dd077`, run `36930936152`)

- Input: `resolved.txt` (6 hosts)  
- DIRECT + Tor → `ports.txt=0`  
- `port_scan.json`: **ERROR** (ERROR ≠ EMPTY **held**)  
- `naabu.log`: FTL no valid ipv4/ipv6  
- live hosts: 21  
- Health: DEGRADED for Nuclei 44.7%; **did not** highlight port ERROR (fixed in `cd536a1`)

### Code on main after repair commits

| Commit | Role |
|--------|------|
| `28dd077` | DIRECT-first, resolved input, phase status |
| `1491f1f` | exit codes, `naabu_portscan.log`, synthetic tests |
| `cd536a1` | dnsx IP pre-resolve, no-cdn retry, health port ERROR flag |

## 4. NEXT (after Port Scan closed)

**Health Contract** pipeline-wide — not active until Port Scan VERIFIED or explicitly BLOCKED.

## 5. DO NOT TOUCH NOW

Health Contract bulk, Provenance redesign, Nuclei/Arjun/Corsy engine rewrites, Smart Fuzz redesign, new engines, SRA merge, global `|| true` removal, infra.

## 6. REFERENCE ONLY

Gap D, Gap I, Submon DNS (`e110544` / #313), response-diff INTERESTING (unless regression).

## 7. EXECUTION LOOP

SYMPTOM → FIRST BAD STAGE → EVIDENCE → ROOT CAUSE → BLAST RADIUS → SMALLEST FIX → REGRESSION → LIVE VERIFY → STATUS  

Commit ≠ VERIFIED.

## 8. STOP RULE

After active problem closed → **STOP**. Next problem only after this file is updated.

## 9. Project map

BugBountyCI = Recon/Discovery/Observation. Not security-research-agent.

## 10. Principle

truthful observation > impressive output · evidence > assumption · known limitation > fake success
