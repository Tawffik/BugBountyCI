# BugBountyCI — PROJECT STATE

> Canonical operational state for implementation agents.
> This is CURRENT STATE, not project history.
> Reconcile against repository + run evidence before any code change.

## 1. Identity

| Field | Value |
|-------|--------|
| Repository | `Tawffik/BugBountyCI` |
| Default branch | `main` |
| **Current HEAD** | **`1491f1f`** (`fix(ports): preserve naabu exit codes; isolate portscan log for ERROR≠EMPTY`) |
| Parent of port-path fix | `28dd077` (`DIRECT-first naabu; resolved input; ERROR≠EMPTY phase status`) |
| Last state reconciliation | 2026-10-02 (from HEAD + Zero Track **#103** artifacts) |

**Contradiction vs older baseline:** some notes still say HEAD=`28dd077`. **Repository truth is `1491f1f`.** Do not reset to `28dd077`.

---

## 2. Source of Truth

When sources disagree:

1. Current repository code
2. Current run artifacts / logs
3. **This `PROJECT_STATE.md`**
4. Notion Fix Control Center
5. `docs/ENGINEERING_LEDGER.md`
6. Master Architecture (Notion)
7. Older notes / chat history

An old commit never proves that a current problem is solved.

---

## 3. CURRENT ACTIVE WORK

| Field | Value |
|-------|--------|
| Active Gate | **P0 — Zero Track Reliability** |
| Active Problem | **Port Scan — discovery still fails (FTL); classification honesty** |
| Status | **VERIFYING** (ERROR semantics proven on #103; **port discovery still BLOCKED**) |

Only one active priority is allowed at a time.

### What #103 proved (SHA `28dd077`)

| Check | Result |
|-------|--------|
| Input | `resolved.txt` (**6** hosts) — preferred path used |
| DIRECT attempted | yes → `ports=0` |
| Tor fallback | yes (`naabu DIRECT returned 0 ports — Tor fallback`) |
| `ports.txt` | **0** lines |
| `meta/phases/port_scan.json` | **`status":"ERROR"`**, `detail":"ports=0"` |
| `logs/naabu.log` | **FTL** `no valid ipv4 or ipv6 targets were found` (repeated) |
| Live hosts | **21** in `live.txt` |

**Invariant on #103:** `TOOL ERROR ≠ EMPTY` — **held** (phase=ERROR, not EMPTY/OK).

**Discovery:** still **BLOCKED**. DIRECT-first did **not** eliminate FTL; hostname/target resolution for naabu still fails on this path. `ports=0` remains **not** evidence of “no open ports.”

### What `1491f1f` added (not live-verified on a completed run yet)

- Dedicated `logs/naabu_portscan.log` (avoid ASN poisoning shared `naabu.log`)
- Preserve `DIRECT_RC` / `TOR_RC` (timeout → ERROR when ports=0)
- Synthetic tests: `scripts/tests/test_port_scan_status.sh`

No Zero Track terminal run on **`1491f1f`** yet → do not claim full LIVE VERIFIED for that commit.

---

## 4. ROOT CAUSE (historical + current)

### Historical (#100 / #101)

```text
live hosts > 0
ports.txt = 0
FTL: Could not run enumeration: no valid ipv4 or ipv6 targets were found
```

Contributing factors then:

- Tor-only naabu
- hostname input
- DNS/target resolution failure on that path
- failure swallowed → looked like “no ports”

### Current (#103 on `28dd077`)

Same **FTL** after **DIRECT + Tor** on `resolved.txt`.  
So the root is **not fully** “Tor-only only.” Deeper causes remain candidates (hostname vs IP for naabu, runner DNS, permissions, etc.) — **investigate under this active problem only**; do not expand to Health Contract yet.

---

## 5. CURRENT FIX (code on main)

| Commit | Change |
|--------|--------|
| `28dd077` | prefer `resolved.txt`; DIRECT-first; Tor if ports=0; `port_scan` phase OK\|EMPTY\|ERROR\|NOT_RUN |
| `1491f1f` | exit-code preservation; `naabu_portscan.log`; synthetic classification tests |

Phase artifact path:

```text
results/<run>/meta/phases/port_scan.json
```

Rule:

```text
ERROR ≠ EMPTY
```

---

## 6. VERIFICATION STATE

| Field | Value |
|-------|--------|
| Latest relevant run | **Zero Track #103** |
| Run ID | `36930936152` |
| Job ID | `110599719078` |
| Target | `nuva.finance` |
| Run conclusion | **`completed` / `success`** (job green ≠ discovery healthy) |
| SHA | **`28dd077`** (not `1491f1f`) |

**Required proof status:**

| Evidence | #103 |
|----------|------|
| port-scan input | yes — `resolved.txt` (6) |
| DIRECT attempt | yes |
| Tor fallback | yes |
| `ports.txt` | yes — **0** |
| `naabu.log` | yes — **FTL** |
| `port_scan.json` | yes — **ERROR** |
| Pipeline Health | present; must not treat ports as clean |

**Do not mark Port Scan VERIFIED** until discovery produces real ports **or** a documented accepted limitation with ERROR remaining truthful on `1491f1f+`.

---

## 7. NEXT ELIGIBLE PROBLEM

After Port Scan is **VERIFIED** or explicitly **BLOCKED** (control process update):

```text
P0 — Health Contract: ERROR ≠ EMPTY (pipeline-wide)
```

Do **NOT** start Health Contract while Port Scan remains the active problem.

---

## 8. DO NOT TOUCH NOW

Until the active problem is closed, do not start:

- Health Contract implementation (beyond ports already in place)
- Provenance redesign
- Nuclei investigation
- Arjun / Corsy investigation
- Smart Fuzzing redesign
- New detection engines
- Security Research Agent architecture
- Workflow-wide refactor
- Global removal of `|| true`
- VPN / VBN / network architecture changes

---

## 9. REFERENCE ONLY

Historical fixes — not active work unless regression evidence appears:

- Gap D — Smart Fuzz fallback semantics
- Gap I — Parameter Intelligence ordering
- DNS collapse / Submon baseline reliability (`e110544`, Submon #313)
- Response-diff false INTERESTING (partial)

---

## 10. REQUIRED EXECUTION LOOP

```text
SYMPTOM
→ FIRST BAD STAGE
→ EVIDENCE
→ ROOT CAUSE
→ BLAST RADIUS
→ SMALLEST FIX
→ REGRESSION TEST
→ LIVE VERIFICATION
→ CURRENT STATUS
```

A commit alone does not mean VERIFIED.

---

## 11. AGENT STARTUP PROTOCOL

Before changing code, an agent MUST:

1. Read **this** `PROJECT_STATE.md`.
2. Inspect current git HEAD / status.
3. Inspect current repository + latest run evidence.
4. Determine the **ACTIVE PROBLEM**.
5. Confirm the requested change belongs to that problem.
6. If it does not → **STOP**.
7. If this file conflicts with repo/run evidence → **STOP** and reconcile state first.

Never use chat history as the authority for current state.

---

## 12. STATE TRANSITIONS

Allowed: `OPEN` | `IN_PROGRESS` | `VERIFYING` | `VERIFIED` | `BLOCKED` | `REFERENCE_ONLY`

| State | Meaning |
|-------|---------|
| OPEN | work required |
| IN_PROGRESS | implementation/testing active |
| VERIFYING | implementation exists; evidence incomplete or discovery still failing |
| VERIFIED | repo + validation/live evidence prove behavior |
| BLOCKED | evidence or dependency unavailable |
| REFERENCE_ONLY | historical; never active |

---

## 13. STOP RULE

After the active problem is completed:

```text
STOP.
```

Do not automatically start the next problem. Next becomes ACTIVE only after this file is explicitly updated.

---

## 14. CURRENT PROJECT MAP

```text
BugBountyCI  →  Recon / Discovery / Observation producer
```

Does **not** become `Tawffik/security-research-agent`. Keep architectural separation.

---

## 15. IMPORTANT PRINCIPLE

```text
truthful observation  >  impressive output
evidence              >  labels
verification          >  anomaly
current repo/run      >  historical memory
```

---

## 16. Existing control files

| Path | Role |
|------|------|
| `.agent/PROJECT_STATE.md` | **Canonical current state (this file)** |
| `.agent/CURRENT_TASK.md` | **Not present** — do not invent unless required |
| `.agent/STATE.json` | **Not present** — do not invent for symmetry |
| `docs/ENGINEERING_LEDGER.md` | Historical memory + evidence log |
| Notion Fix Control Center | Human-facing queue / history |

---

*End of PROJECT STATE. Update this file when HEAD, active problem, or verification status changes.*
