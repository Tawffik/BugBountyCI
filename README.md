# BugBountyCI — Zero Track

**Authorized reconnaissance and security-signal pipeline on GitHub Actions.**

This repository is a **CI system**: phased discovery, bounded active checks, honest health, and operator-facing triage surfaces.  
It is **not** an autonomous AI agent that “finds and confirms bugs by itself.” Optional AI steps exist only as soft helpers; the core product is deterministic tooling + ranking + review queues.

> **Project memory:** [`docs/ENGINEERING_LEDGER.md`](./docs/ENGINEERING_LEDGER.md) — goals, bug history, merges, and open gaps. Chat sessions do not persist; the ledger does.  
> **Ops status (Notion):** Fix Control Center synced **2026-10-30** (main tip through PR **#96**). See Notion Fix Control Center + `docs/ENGINEERING_LEDGER.md`.

[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Zero%20Track-2088FF?logo=githubactions&logoColor=white)](https://github.com/Tawffik/BugBountyCI/actions)
[![Workflow](https://img.shields.io/badge/Pipeline-~75%20named%20steps-success)](./.github/workflows/zero-track-hunter.yml)
[![Scope](https://img.shields.io/badge/Scope-Authorized%20targets%20only-orange)](#legal--ethics)
[![Nuclei](https://img.shields.io/badge/Bulk%20Nuclei-OFF%20(intentional)-lightgrey)](#what-zero-track-is-not)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

---

## North Star (operator outcomes)

After **one authorized run**, you should answer within minutes:

1. **Did the funnel work?** — DNS → live → URLs → JS (see `triage/GATE_0.md`)
2. **What do I open first?** — not twenty random folders (`GATE_0` → secrets/exposure/hunter)
3. **Does empty mean clean, or starved / blocked / partial?** — phase health + RRP, not “0 findings = safe”

---

## What Zero Track is

| Layer | Role |
|--------|------|
| **Discovery** | Subdomains, ASN/CIDR inventory, live hosts, ports, URL corpus |
| **Enrichment** | JS collection/deep extract, parameters, historical correlation |
| **Detection engines (V1)** | Access-Control, SSRF, Open Redirect, Smart 403, Cloud exposure — **signals / LEADs**, not auto-confirmed vulns |
| **Ranking** | Smart-fuzz response diffs, metrics, unified hunter queue |
| **Operator surfaces (RRP)** | `GATE_0`, `SECRETS_REVIEW`, `EXPOSURE_QUEUE`, conservative triage |
| **Export / health** | Artifacts, export caps metadata, engine/phase health |

Primary workflow: [`.github/workflows/zero-track-hunter.yml`](./.github/workflows/zero-track-hunter.yml) (~75 named steps).

```text
Authorized scope
  → Discovery (subs / ASN inventory)
  → Live surface + ports (promotion under resource caps)
  → URL collection + quality gates
  → JS / secrets / parameters
  → Detection engines (bounded)
  → Historical pivot + validation budget
  → Hunter queue + triage / RRP
  → Artifacts + health
```

---

## What Zero Track is not

- **Not** a guarantee of paid bounties  
- **Not** “every Hunter row = confirmed vulnerability”  
- **Not** automatic SI → Hunter promotion of secrets  
- **Not** bulk **Nuclei** in this pipeline (**NOT_RUN** by design; CVE-scoped work belongs elsewhere, e.g. VulnRadar)  
- **Not** “raise ASN/live/port caps until numbers look like old runs” — inventory can be large while **promotion is capped** (`meta/resource_caps.json`, now summarized in `GATE_0`)  
- **Not** full Notion dorking manuals executed by default (`docs/dorking_engine.py` remains **IMPLEMENTED_NOT_INVOKED** until disclosure-desk + contracts)

Optional multi-provider **AI Agent** steps may run when API keys exist; they are **assistive**, not the definition of the system.

---

## Current system capabilities (accurate as of main `057a8d9+` / PR #96)

### Discovery and gates
- Passive/active subdomain sources, resolve, live probe, ports  
- **ASN/CIDR:** full inventory retained; live/port **promotion capped** (documented in GATE_0 — low live ≠ asnmap failure)  
- URL merge with passive sources; quality gates for live/URL surface  
- `triage/GATE_0.md` + `meta/funnel_gate.json` — funnel integrity verdict  

### JavaScript and secrets
- JS file harvest + deep extract (LinkFinder, etc.)  
- Secret detectors → SI-2 / SI-4 classification; **review via SECRETS_REVIEW**, not auto-confirm  
- Stable `js/endpoints.txt` materialized from LinkFinder API/WEB routes  

### Information disclosure family
- Path probes (git / backup / config / listing / errors) with body-aware classification where wired  
- **Derived probes** (e.g. `.map` / backup suffixes from URL harvest)  
- **Archive sensitive probe** early after URL collection (budget 25) + export refresh (40)  
- **Disclosure Desk** + **Easy-Wins** + **Smart Dork Board** via RRP triage bundle  
- **QUALITY_GATE** `disclosure_family_rollup` (probes / derived / maps / archive / github status)  
- **Historical** host+path pivot + bounded validation  
- Representation differential (observational)  
- **Cloud Exposure V1:** provider clues — **never auto-confirmed**  
- Path hits often **empty on hardened targets** = EMPTY_VALID, not a dead stage; GitHub **RATE_LIMIT ≠ no exposure**  

### Detection engines
| Engine | Intent |
|--------|--------|
| Access-Control V1 | Diff signals → LEAD / NOISE |
| SSRF V1 | No OOB ⇒ not HIGH_SIGNAL/CONFIRMED |
| Open Redirect V1 | Candidates / evidence honesty |
| **Smart 403** | Bounded adaptive bypass techniques (Notion-informed); **LEAD only** |
| **Smart Fuzz V1** | Target wordlist (vocab+wolf+seeds); hostname-first; operator_summary; body samples — **signal not vuln** |
| Hunter queue | Unified ranked markdown for humans |

### Operator RRP
- `triage/GATE_0.md` · `triage/QUALITY_GATE.md` · `triage/DELTA.md`  
- `triage/DISCLOSURE_DESK.md` · `triage/EASY_WINS.md` · `triage/SMART_DORK_BOARD.md`  
- `triage/SECRETS_REVIEW.md` · exposure / opportunity boards when produced  
- `triage/EXPOSURE_QUEUE.md`  
- `triage/triage_summary.json` — **`auto_confirmed: 0`** by policy  
- `detection/hunter_queue.md`  

### Health and exports
- `meta/engine_health.json`, phase JSON under `meta/phases/`  
- `meta/export_caps.json` when URL export is truncated  
- Pipeline health markdown synced to overall status after exports  

---

## After a run — open this order

1. `triage/QUALITY_GATE.md` — stage honesty (ERROR≠EMPTY)
2. `triage/GATE_0.md` — funnel + ASN inventory vs caps
3. `triage/DELTA.md` — vs previous run when available
4. `triage/EVIDENCE_GRAPH.md` / `triage/OPPORTUNITY.md` — links + review order  
2. `triage/SECRETS_REVIEW.md` / `triage/EXPOSURE_QUEUE.md`  
3. `detection/hunter_queue.md`  
4. `detection/smart_403_summary.json` (if present)  
5. `detection/cloud_exposure_summary.json`  
6. `triage/triage_summary.json`  
7. `meta/engine_health.json` / `meta/pipeline_health.md`  

Artifacts are uploaded per workflow run under Actions.

---

## Design contracts (non-negotiable)

| Contract | Meaning |
|----------|---------|
| Authorized targets only | Scope check; no “scan everything for activity” |
| LEAD ≠ CONFIRMED | Human verification required for impact |
| Caps stay | Do not “fix” low live counts by removing caps |
| Nuclei bulk off | Zero Track is recon + signal ranking |
| SI→Hunter off | Secrets stay in review surfaces |
| Soft-fail phases | One tool failure should not erase the run’s operator surfaces |

---

## Quick start

### 1. Clone

```bash
git clone https://github.com/Tawffik/BugBountyCI.git
cd BugBountyCI
```

### 2. Secrets (optional)

Repo → **Settings → Secrets and variables → Actions**

| Secret | Purpose |
|--------|---------|
| `DISCORD_WEBHOOK` | Summary notifications |
| `GROQ_API_KEY` / `GEMINI_API_KEY` / … | Optional AI helper phases |
| `PDCP_API_KEY` | ProjectDiscovery cloud features where used |
| `URLSCAN_API_KEY` / `VIRUSTOTAL_API_KEY` | Optional passive enrichment (if configured) |
| `AUTH_COOKIE` / `AUTH_HEADER` | Optional authenticated context |

### 3. Run Zero Track

**Actions → Zero Track / AI Autonomous Hunter → Run workflow**

Typical inputs:
- **Target** domain you are authorized to test  
- Prefer **light** / bounded mode for verification runs  
- Keep default WAF flood flags off; prefer Smart 403 path  

Only run against **in-scope, authorized** assets.

---

## Repository map

| Path | Role |
|------|------|
| `.github/workflows/zero-track-hunter.yml` | Main monolith pipeline |
| `pipeline/detection/` | Detection engines + hunter queue builder |
| `pipeline/scope.py` | Shared in-scope helpers |
| `scripts/` | RRP, historical, exports, triage, phase helpers |
| `docs/ENGINEERING_LEDGER.md` | Engineering history and decisions |
| `docs/RESULTS_RECOVERY_PROGRAM.md` | RRP design |
| `docs/dorking_engine.py` | Dorking prototype (**not** default-invoked) |
| `tests/` | Offline regression for engines and gates |

---

## Roadmap highlights (honest)

**Done recently:** conservative triage, Smart 403 + RD fix, Cloud Exposure V1, hunter queue integrity, JS endpoints path, health/SARIF honesty, ASN visibility in GATE_0.

**Next (see ledger / Fix Control Center / [`docs/INFO_DISCLOSURE_EXECUTION_PLAN.md`](./docs/INFO_DISCLOSURE_EXECUTION_PLAN.md) · [`docs/PLAYBOOK_ZERO_TRACK_INTEGRATION.md`](./docs/PLAYBOOK_ZERO_TRACK_INTEGRATION.md)):**
1. One **normal** (or light) authorized run on tip **#96+** → Desk + Easy-Wins + QUALITY_GATE `disclosure_family_rollup` + smart-fuzz `operator_summary`  
2. **Disclosure Desk** — single operator markdown aggregating ID/exposure family outputs  
3. Stage-derived path probes (e.g. `.map` from JS inventory) under budget  
4. Bounded GitHub passive query slice with provider status honesty  
5. Dorking enablement only after contracts/benchmarks — still **not** default Hunter feed  

---

## Legal / ethics

Use only on systems you own or are **explicitly authorized** to test under a bug bounty or written agreement.  
Misuse can be illegal. Authors are not responsible for unauthorized scanning.

---

## License

[MIT](./LICENSE)

---

## Maintainers

Built and iterated as a **pipeline product** for authorized bug-bounty reconnaissance — ranking and review first, not AI theater.
