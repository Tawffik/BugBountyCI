# BugBountyCI — Full-System Intelligence & Effectiveness Audit

**Audit date:** 2026-10-09  
**HEAD at audit write:** `cc51e84`  
**Canonical ledger:** `docs/ENGINEERING_LEDGER.md`  
**Scope:** Tawffik/BugBountyCI only (SRA downstream; VulnRadar owns bulk Nuclei + subdomain monitor)

---

## 0. Executive assessment

### What BugBountyCI is now
An **authorized recon → observation → relationship → research-queue** pipeline (Zero Track), not a vulnerability-confirmation agent and not a bulk Nuclei farm.

### Strengths (evidence-backed)
| Strength | Evidence |
|----------|----------|
| Truthful health semantics | DEGRADED when Arjun/Nuclei partial; ERROR≠EMPTY contracts in phases |
| Historical → validation → Hunter | #122–#135 lineage; scheme-only redirects filtered from Hunter |
| Representation Differential closed | Live-verified earlier cycle; not reopened |
| Cross-engine RESEARCH_CONTEXT | #139 RC=13, #140 RC=40, #141 RC=13 after post-export rebuild |
| SI quarantine + SI→Hunter OFF | #141: suppressed=101; SI not in hunter engines |
| Host/URL export correctness | Fixed urlparse shadow; IP cap 200; #141 hosts_modeled=245 |
| Nuclei ownership boundary | Bulk NOT_RUN / MOVED_TO_VULNRADAR on #141 |
| Timeout-root fix (hostname_targets) | `cc51e84` systemic list for expensive HTTP probes |

### Largest gaps
1. **Runtime waste on pre-`cc51e84` SHAs:** Info-disclosure 1681s on #142/#143 (full 28m budget).
2. **#142/#143 still running on `6ac4433`** — do not verify `cc51e84` from them.
3. **URL yield ≪ live host count** largely due to IP enrichment, not necessarily crawl failure.
4. **Arjun upstream AttributeError** still possible; input quality improved, tool bug remains.
5. **Autonomy is session/prompt-driven**, not a durable background orchestrator.
6. **Notion lag** partially addressed; older FCC sections still historical noise.

### Overall reliability
**Operationally useful for research queues on authorized targets**, with honest DEGRADED states.  
**Not** a finished “max intelligence” product; highest remaining value is **cost-bounded execution + deeper use of existing relationships**, not new scanners.

**Project status:** **CONTINUE** (not PROJECT_COMPLETE).

---

## 1. Phase 0 — Current runs baseline

| Run | Target | SHA | Status (at audit) | Notable timings |
|-----|--------|-----|-------------------|-----------------|
| **#142** `37939557700` | capital.com | `6ac4433` | **in_progress** | Info-disc **1681s**; Targeted 1410s; URL 1205s; Screenshots running |
| **#143** `37939620457` | superdrug.com | `6ac4433` | **in_progress** | Info-disc **1681s**; URL 1759s; AI Infra 1191s |
| **#141** `37875044705` | capital.com | `6ac4433` | **success** | **Primary verified baseline** for gates on this SHA |
| HEAD | — | **`cc51e84`** | — | hostname_targets root fix **after** #141/#142/#143 SHA |

**Rule:** SUCCESS ≠ every phase healthy. #141 overall DEGRADED (Arjun PARTIAL only after Nuclei removal).

**Cancellation:** #142/#143 are progressing (not stuck at 0 steps). Redundant vs HEAD verification, but not frozen — cancel only if operator wants to free runners for `cc51e84` light run.

---

## 2. Historical run window (~Oct 2–9 2026)

API sample: Zero Track runs **#114–#143** (30 most recent workflow runs).

| Band | Runs | Pattern |
|------|------|---------|
| #114–#122 | success + some cancel | Historical/representation build-out; runner friction |
| #123–#126 | cancelled | Runner/queue issues (Sengi era residual) |
| #127–#133 | success | Reliability + Hunter API seeds + tip-SHA |
| #134–#137 | success | SI + scheme filter + capital depth |
| #138 | cancelled | Superseded quickly |
| #139–#141 | success | Export/RC/IP-cap/Nuclei-move path |
| #142–#143 | in_progress | Same SHA as #141; **repeat cost** without `cc51e84` |

**Incomparable across targets:** capital.com ≠ nuva.finance ≠ app.aikido.dev ≠ superdrug.com — do not treat raw URL counts as a single trend line.

### Documented live metrics (do not mix runs)

| Metric | #134 capital | #139 capital | #141 capital | #140 aikido |
|--------|-------------:|-------------:|-------------:|------------:|
| SHA | 5b8941d | c49fbd0 | 6ac4433 | df3be1c |
| hosts_modeled | (pre IP-cap era varies) | 14378 | **245** | — |
| urls_modeled | — | 224 | 227 | 1559 |
| RESEARCH_CONTEXT | 0 (pre fix) | **13** | **13** | **40** |
| SSRF HIGH_SIGNAL | filtered later | 2 (http+https) | **1** (deduped) | — |
| Nuclei | PARTIAL high errors | PARTIAL ~46% | **NOT_RUN VulnRadar** | PARTIAL ~52% |
| SI suppressed | ~100 | 101 | **101** | — |

---

## 3. Capability matrix (condensed)

| Component | Purpose | Live evidence | Decision |
|-----------|---------|---------------|----------|
| Subdomain enum | Discovery | Runs complete; ASN variance | **Keep** |
| Port scan | Coverage | OK on recent; prior Tor failures fixed | **Keep** |
| Live probe | HTTP surface | live.txt large via IPs | **Keep**; consumers must use hostname_targets |
| URL collection | Crawl/archive | Long runtime; high value when APIs exist | **Keep**; prefer hostname_targets |
| JS / LinkFinder | API routes | Feeds Hunter INTERESTING | **Keep** |
| Historical pivot+validate | Current reachability | Closed loop | **Keep / protected** |
| Representation differential | Alt representations | Closed | **Keep / protected** |
| Smart fuzz | Response diffs | Honest EMPTY/NO_MATCH states | **Keep** |
| SSRF engine | Differential signal | HIGH_SIGNAL with OOB honesty | **Keep** |
| Access-control | LEAD candidates | #141 LEAD×7 | **Keep** |
| Hunter queue | Research prioritization | RC + engines labeled | **Keep** |
| SI (js_deep→canonical) | Secret-shaped leads | Quarantine; not Hunter | **Keep bounded**; no auto-confirm |
| Info-disclosure | Git/backup/config | **Timeout waste pre-fix** | **Repaired** path + hostname_targets |
| Arjun | Hidden params | PARTIAL + upstream bug | **Constrain inputs**; tool still flaky |
| Nuclei bulk | CVE templates | Months of 0+errors | **Retire from Zero Track** → VulnRadar |
| Subdomain Monitor workflow | Continuous assets | Deprecated in BBCI | **VulnRadar** |
| Screenshots / Nikto / CMS | Aux coverage | Costly; low intelligence reuse | **Constrain** via hostname_targets |

---

## 4. Data / intelligence flow

```
Scope/target
 → DNS/subdomains → live probe (+ IP enrichment)
 → hostname_targets (cc51e84) ──► expensive HTTP probes
 → URLs/JS → endpoints/relationships
 → historical + representation + smart-fuzz + detection engines
 → write_pipeline_exports → hunter_queue (post-export)
 → recon_export.v1 / sra_handoff summary
 → [boundary] ReconResultAdapter → SRA
```

**Loss points historically**
- Relationships written after Hunter → RC=0 (fixed 4ae2fc9)
- urlparse shadow → empty hosts/urls (fixed c49fbd0)
- IP flood in consumers → timeouts (fixed cc51e84 at source)
- SI raw → noise without quarantine (quarantine path exists)
- Nuclei errors presented near “clean” risk (explicit NOT_RUN now)

---

## 5. External benchmark (directional, not scored)

| External practice | BBCI stance |
|-------------------|-------------|
| Prefer evidence over volume (OWASP testing process) | Aligned via Hunter research queue + health honesty |
| Scope/authorization boundaries | Workflow inputs + target checks |
| Nuclei as targeted verification | Aligned post-move to VulnRadar CVE-id model |
| Continuous asset diff | VulnRadar monitor, not Zero Track |
| Do not equate scanner green with security | Explicit in contracts |

No numeric “score” claimed — measurements are run-specific artifacts, not a shared benchmark suite with ground truth.

---

## 6. Information Disclosure deep note

| Dimension | Finding |
|-----------|---------|
| Technique | Path probes: git, backups, configs, dir listing, error triggers |
| Failure mode | Full expensive_targets × paths × Tor → **1681s** |
| Fix | Hostname cap, DIRECT-first, soft deadline, phase JSON; plus **hostname_targets** upstream |
| Blind spots | Authenticated disclosure, JS-embedded secrets (handled partly by SI), cloud metadata beyond basic SSRF |
| Priority | Reliability first (done); content classification depth next only if live shows residual value |

---

## 7. Internal benchmark (minimal, reproducible)

Use **same target + hunting_mode + comparable SHA band**:

1. `information_disclosure` phase elapsed < 900s soft / never peg full timeout  
2. `hosts_modeled` IP portion ≤ 200 LIVE_IP  
3. `RESEARCH_CONTEXT` ≥ 1 when relationships.jsonl has HISTORICAL∩JS or JS∩live  
4. Nuclei phase `NOT_RUN` + track external_vulnradar  
5. Hunter engines must not include SI  
6. Health must not mark Nuclei errors as CLEAN  

Baseline proof: **#141** for (2)(3)(4)(5)(6); (1) requires post-`fcc838d`/`cc51e84` live run.

---

## 8. Gap register (ranked)

| ID | Gap | Evidence | Priority | Status |
|----|-----|----------|----------|--------|
| G1 | Expensive probes on IP-heavy lists | #142/#143 1681s | P0 | **FIXED** `cc51e84` |
| G2 | Info-disc internal budget | same | P0 | **FIXED** `fcc838d` |
| G3 | Live verify hostname_targets | HEAD ≠ #142 SHA | P1 | **READY** (light run) |
| G4 | Arjun upstream AttributeError | #141 log | P2 | Constrained; tool limit |
| G5 | Notion historical noise vs HEAD | FCC age | P2 | Partial update done |
| G6 | Deeper API/auth object intelligence | AC LEAD present; limited corroboration | P2 | Not started |
| G7 | Durable autonomous orchestrator | session model | P3 | Document limitation only |

---

## 9. Implementation already landed this cycle

- `fcc838d` — info-disclosure bounds  
- `fa35de5` — Arjun hostname filter  
- `cc51e84` — **hostname_targets workflow-wide**  
- Ledger redirect + #141 live-closed notes  
- Notion FCC additive blocks (POST-#141, Arjun)

---

## 10. Next READY

1. When #142/#143 complete → harvest (expect old timeout pattern); **do not** treat as verification of `cc51e84`.  
2. One **light** authorized run on **`cc51e84+`** → measure info-disc elapsed + hostname_targets count.  
3. Only then consider G6 (API/auth depth) if evidence supports.

**Autonomy note:** Continuation requires an invoking session; no durable wake-up controller is implemented in-repo.
