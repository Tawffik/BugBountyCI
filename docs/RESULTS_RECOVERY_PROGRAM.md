# Results Recovery Program (RRP)

**Status:** ACTIVE PLAN (2026-10-20)  
**Goal:** Make Zero Track reliably surface **operator-actionable** leads (`.env` / info-disclosure / high-confidence JS secrets / GitHub recon) without breaking `main` integrity contracts (SI→Hunter stays OFF; no false CONFIRMED).

**North star for the operator:** After one authorized `light` run on current `main`, the artifact must answer in under 5 minutes:

1. Did the funnel work? (`meta/phases`, `urls/all.txt` non-empty, DNS/live honest)
2. What should I open first? (`triage/SECRETS_REVIEW.md` + `info_disclosure/` + `js/secrets_high*`)
3. Is empty = clean, or empty = starved/error?

This program does **not** promise paid bounties. It restores the **signal path** that months of work already built but operators could not see or trust.

---

## 0. What is already fixed on `main` (do not re-break)

Evidence: `docs/ENGINEERING_LEDGER.md` through PR **#51** (approx. HEAD series Oct 2026).

| Area | PRs / notes | Rule |
|------|-------------|------|
| IP flood → live/scan_order | #17, #24, #29, #30 | Keep caps; raise only with resource_caps.json proof |
| hostname_targets ranking | #42, `hostname_targets.py` | Prefer admin/api/test |
| Health honesty | #22, #36–#38 | Never let MD say HEALTHY over phase error |
| Scope on parameter map | #39–#40 | TARGET / profile required |
| Smart-fuzz structural paths | #41, #46–#48 | Wordlist from target, not noise |
| GitHub recon attribution | #51 | Domain-in-body + ID paths |
| Info-disclosure body classifier | `classify_info_disclosure_body.py` | Keep |
| Historical prefer-https | earlier PRs | Keep |
| uro empty-all.txt | documented fix in superdrug #14 RCA | **Verify still present in YAML** on next light run |

**Do not** mass-merge experimental branches that delete `zero-track-hunter.yml` or disable integrity flags.

---

## 1. Remaining gaps that still hide results

| ID | Gap | Operator symptom | Priority |
|----|-----|------------------|----------|
| **RRP-1** | Secrets land in SI quarantine; **no first-class review doc** in triage | “Pipeline ran, I see nothing to submit” | **P0** |
| **RRP-2** | Info-disclosure hits not merged into one ranked queue with secrets | Operator opens 6 folders | **P0** |
| **RRP-3** | Funnel integrity not summarized in one gate file | 0 findings misread as clean | **P0** |
| **RRP-4** | `dorking_engine` IMPLEMENTED_NOT_INVOKED | No Google/GitHub dork path in CI | **P1** |
| **RRP-5** | Live E2E still “pending” for several merges | Trust gap on production SHA | **P1** |
| **RRP-6** | Overlapping static path matrices (info-disc vs security analysis) | Budget waste | **P2** |
| **RRP-7** | Monolith YAML hard to patch safely | High regression risk | **P2** (later modular) |

**Explicit non-goals for RRP v1**

- Turning SI into Hunter CONFIRMED automatically  
- Re-enabling bulk Nuclei inside Zero Track  
- Raising IP caps to pre-#17 levels  
- Guaranteeing bounty payouts  

---

## 2. Branch strategy (professional, main-safe)

```text
main  (protected behavior)
  │
  ├── docs/results-recovery-program     ← this document + checklists
  │
  ├── feat/rrp-1-secrets-review-md      ← P0 operator surface
  ├── feat/rrp-2-exposure-unified-queue ← merge info_disclosure + secrets_high
  ├── feat/rrp-3-funnel-gate-summary    ← GATE_0.md in artifact root
  ├── feat/rrp-4-optional-dorking-job   ← separate workflow_dispatch job
  └── test/rrp-e2e-light-checklist      ← docs only: acceptance run protocol
```

**Rules**

1. One concern per branch / PR.  
2. Offline tests required for any Python change (`pytest`).  
3. No direct commits to `main` for RRP work.  
4. Merge order: **RRP-1 → RRP-3 → RRP-2 → RRP-5 verification → RRP-4**.  
5. After each merge: one **authorized light** run; paste gate metrics into ledger.  
6. Draft PRs until offline tests + review checklist pass.

---

## 3. Work packages

### RRP-1 — `triage/SECRETS_REVIEW.md` (P0)

**Problem:** High-confidence secrets exist under `js/` / `js_deep/` / SI outputs but are not the first file the operator opens.

**Deliverables**

- Script: `scripts/build_secrets_review.py`
  - Inputs (best-effort, missing = skip with note):
    - `js/secrets_high.txt` (or equivalent)
    - `js_deep/secretfinder_secrets.txt`, `trufflehog_findings.json`, `gitleaks_findings.json`
    - SI retained list if present
  - Filters: example/test/fixture path markers; obvious placeholders (`YOUR_`, `changeme`, `sk_live_...` ellipsis)
  - Output: `triage/SECRETS_REVIEW.md` + `triage/secrets_review.json`
  - Labels: `REVIEW` only — never `CONFIRMED`
- Wire call near existing triage step in workflow (continue-on-error: true)
- Tests: synthetic fixtures under `tests/fixtures/secrets_review/`

**Acceptance**

- Empty inputs → markdown states `NO_INPUTS` + which paths missing  
- Fixture with one AWS-shaped + one example path → only AWS-shaped in REVIEW section  

### RRP-2 — Unified exposure queue (P0)

**Problem:** `.env`-class hits live in `info_disclosure/*` while secrets live elsewhere.

**Deliverables**

- `scripts/build_exposure_queue.py` merges:
  - info_disclosure config/git/backup hits classified sensitive
  - SECRETS_REVIEW entries
  - github_recon retained lines (post-#51 filter)
- Output: `triage/EXPOSURE_QUEUE.md` (top 30, ranked)
- Ranking: live host path > github file > js pattern; sensitive body class > path-only

**Acceptance**

- On fixture run, `.env` path with KEY= style body ranks above generic 404 path  

### RRP-3 — Funnel gate summary (P0)

**Problem:** Operators treat `0 findings` as “target clean”.

**Deliverables**

- `scripts/build_funnel_gate.py` → `triage/GATE_0.md` + `meta/funnel_gate.json`
- Fields:
  - `dns_resolved_count`, `live_hostname_count`, `urls_all_bytes`, `urls_all_lines`
  - `js_files_count`, `info_disclosure_phase_status`
  - `verdict`: `FUNNEL_OK` | `STARVED` | `ERROR` | `PARTIAL`
  - Human one-liner in Arabic+English: do not report “secure” if STARVED/ERROR

**Acceptance**

- Simulated `urls/all.txt` empty + wayback non-empty → `STARVED` not `FUNNEL_OK`  

### RRP-4 — Optional dorking job (P1)

**Problem:** `docs/dorking_engine.py` never runs in CI.

**Deliverables**

- New workflow: `.github/workflows/dorking-optional.yml`
  - `workflow_dispatch` only
  - inputs: target, sources, max dorks
  - requires `GITHUB_TOKEN` secret for code search
  - uploads `dorking/` artifact only
- **Not** merged into the 60+ step hunter until RRP-1–3 stable
- Redaction: no raw secret values in Discord notifications

**Acceptance**

- Manual dispatch on demo mode or rate-limit-safe query completes without touching Zero Track  

### RRP-5 — Live verification protocol (P1)

**Checklist for one authorized light run after RRP-1–3 merge**

```text
[ ] urls/all.txt lines > 0
[ ] meta/funnel_gate.json verdict != ERROR (or explained)
[ ] triage/SECRETS_REVIEW.md exists
[ ] triage/EXPOSURE_QUEUE.md exists
[ ] triage/GATE_0.md exists
[ ] info_disclosure phase elapsed < soft budget
[ ] hostname_targets non-empty when live hostnames exist
[ ] engine_health overall honest if any critical phase error
```

Paste results into `docs/ENGINEERING_LEDGER.md` under a dated RRP section.

### RRP-6 — Path matrix dedup (P2)

Defer until gates pass twice. Then share path list between info-disclosure and security analysis via one generated file.

---

## 4. Mapping old root causes → RRP response

| Historical failure | RRP response |
|--------------------|--------------|
| uro wiped `urls/all.txt` | RRP-3 detects STARVED; re-verify uro fallback still in YAML |
| DNS resolved=0 | RRP-3 + existing DNS_FAILED; no engine expansion until green |
| Info-disc 1681s on IPs | hostname_targets already on main; RRP-5 measures |
| SI 101 suppressed, Hunter empty | RRP-1 surfaces retained + high files without SI→Hunter ON |
| “0 findings = secure” | RRP-3 explicit verdict |
| Dorking unused | RRP-4 isolated job |

---

## 5. Execution order (this week)

| Day | Action |
|-----|--------|
| 0 | Merge this doc PR (`docs/results-recovery-program`) |
| 1 | Branch `feat/rrp-1-secrets-review-md` — implement + tests + draft PR |
| 2 | Branch `feat/rrp-3-funnel-gate-summary` — implement + tests |
| 3 | Branch `feat/rrp-2-exposure-unified-queue` — depends on RRP-1 outputs |
| 4 | Authorized **light** run on soft target; fill RRP-5 checklist |
| 5 | Only if gates OK: `feat/rrp-4-optional-dorking-job` |

---

## 6. Definition of done (program-level)

RRP is **done** when:

1. Three consecutive authorized light runs produce `GATE_0` with `FUNNEL_OK` or honest `PARTIAL` (not silent empty).  
2. Operators report opening `SECRETS_REVIEW.md` / `EXPOSURE_QUEUE.md` first.  
3. No regression in offline test suite.  
4. Ledger documents one live SHA with the checklist above.  

**Not** done when: more scanners added, or SI forced into Hunter, or caps removed to “see more lines”.

---

## 7. Honest expectation

Months of work produced a serious integrity-oriented pipeline. Results felt missing because:

1. Early layers sometimes starved later ones.  
2. Secrets were deliberately quarantined.  
3. Operator UX pointed at Hunter, not secret/info-disclosure folders.  

RRP fixes **visibility + funnel truth + optional dorking**, on branches, without discarding the engineering discipline already paid for on `main`.
