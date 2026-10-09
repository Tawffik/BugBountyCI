# BugBountyCI — Whole-System Capability Audit & Historical Benchmark

**Date:** 2026-10-09  
**HEAD at write:** post-enrichment commit (see ledger)  
**Canonical ledger:** `docs/ENGINEERING_LEDGER.md`  
**Sample:** Zero Track workflow runs **n=50** (2026-09-25 → 2026-10-09)

## 1. Historical sample (API metadata)

| Conclusion | Count |
|------------|------:|
| success | 39 |
| cancelled | 6 |
| failure | 3 |
| in_progress | 2 (#143, #144 at sample time) |

**Limits:** Artifact retention prevents full two-month deep metrics for every run. Deep artifact analysis uses **#141** (capital, `6ac4433`) and **#142** (capital, `6ac4433`) as primary comparable cohort (same target, same tip band).

**Do not mix:** capital.com ≠ superdrug.com ≠ nuva.finance counts.

## 2. End-to-end flow (actual)

```
Scope/target input
 → Subdomain discovery + DNS resolve
 → Live probe (+ port enrichment → live.txt may include many IPs)
 → hostname_targets.txt (cc51e84+) for expensive HTTP consumers
 → URL collection / JS deep / LinkFinder normalize
 → Historical pivot + bounded validation → Hunter RESEARCH/INTERESTING
 → Representation differential (observational)
 → Detection engines (SSRF, AC, open_redirect, smart_fuzz)
 → SI canonicalize + quarantine (SI → Hunter OFF)
 → write_pipeline_exports → engine_health, target_profile, relationships, hunter_queue
 → recon_export.v1 + sra_handoff (boundary: BBCI → Adapter → SRA)
```

**VulnRadar:** bulk Nuclei + continuous subdomain monitor (not Zero Track).

## 3. Capability verdicts (evidence-backed)

| Capability | #141 evidence | Decision |
|------------|---------------|----------|
| DNS / live / ports | resolved=56, verified=74, ports=28610 | Keep |
| URL collection | 227 | Keep; cost high |
| LinkFinder normalize | raw 2850 → API 30 / WEB 923 / STATIC 1793 | Keep |
| Relationships | 1045; JS_TO_ENDPOINT 400; HISTORICAL∩JS 6; JS∩live 24 | Keep |
| Historical validation | validated=40 REDIRECTED; not_run=63 budget | Keep closed |
| Representation | 1 pair NETWORK_ERROR | Keep closed |
| SSRF | non-NOISE=2 | Keep |
| Access control | non-NOISE=7 LEAD | Keep |
| Smart fuzz | DIFFS findings=2 | Keep honest |
| Hunter | HS1 LEAD7 INT27 RC13 | Keep research queue |
| SI | 14 retained / 101 suppressed; not in Hunter | Keep; no filter loop |
| Nuclei bulk | NOT_RUN external_vulnradar | Keep boundary |
| Arjun | PARTIAL | Constrain inputs (done); tool upstream flaky |
| Info-disclosure probes | phase file on newer SHAs; timeout waste pre-fix | Soft budget + hostname_targets |
| AI planning phases | #142 all providers failed | **Operational** (keys/credits); health must not call recon funnel dead if stages produced data |
| Phase observability | historical/representation summaries existed but absent from engine_health.phases on #141 | **FIXED** enrichment in write_pipeline_exports |

## 4. Where value is lost / underused

1. **Runtime on IP-heavy lists** — mitigated by `hostname_targets` (needs live on HEAD+).  
2. **AI keys/credits** — planning phases empty; not a discovery bug.  
3. **Historical not_run=63** — budget bound; intentional.  
4. **Representation NETWORK_ERROR** — environment; not FP.  
5. **engine_health.phases incomplete** — intelligence summaries not attached → **addressed**.  
6. **Access-control LEADs** — human/SRA consumption, not more scanners.  
7. **live_hosts 28k vs verified 74** — modeling/IP enrichment; exports cap IPs.

## 5. Gap register (ranked)

| ID | Gap | Evidence | Priority | Status |
|----|-----|----------|----------|--------|
| G-obs-1 | intelligence summaries not in engine_health.phases | #141 | P1 | **FIXED** this cycle |
| G-live-1 | hostname_targets + flags + AI severity on HEAD | #144 on 3ed22d8 only | P1 | LIVE pending |
| G-ops-1 | AI provider credentials | #142 flags | P1 | External |
| G-arjun | upstream AttributeError | #141 | P2 | Input constrained |
| G-depth-api | deeper authz object correlation | LEAD present; limited multi-engine join | P2 | READY later |
| G-si-loop | further SI filters | Notion forbid | — | **Do not** |

## 6. Selection rule applied

Compared: correlation (already producing RC), Info-disc (timeout mitigated), API depth (needs design), export observability (**actionable offline**).

Selected **G-obs-1** as highest independent READY with proof on #141 artifacts without a new scan.

## 7. AI health severity note

Changing AI-only failure from funnel-BROKEN to DEGRADED is **not** cosmetic: #142 funnel rows were ✅ while overall said stages “produced nothing.” That violated the health report’s own definition. AI remains flagged; recon signal is not declared dead.

## 8. Project status

**CONTINUE** — not PROJECT_COMPLETE. Highest remaining required live work is verification of HEAD features on a finished run at current SHA; operational AI keys are external.
