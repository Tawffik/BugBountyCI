# Information Disclosure / Exposure — Execution Plan

**Status:** PLAN — **Phase 1 Desk + Phase 2 derived probes IMPLEMENTED** (2026-10-27). Phases 3–4 (GitHub slice, dorking) still open.  
**Date:** 2026-10-27  
**Scope:** BugBountyCI Zero Track only  
**Authority:** Chat audit series + Notion (Module 24, Passive Intelligence & Dorking Blueprint, GitHub Dorking Manual, Fix Control Center, Tips) + run #175 evidence + OWASP WSTG alignment  

**Related:** `docs/ENGINEERING_LEDGER.md`, `docs/RESULTS_RECOVERY_PROGRAM.md`, `docs/RRP4_OPTIONAL_DORKING.md`, Notion Fix Control Center update 2026-10-27.

---

## 1. Goal

Make the **information-disclosure family** produce **useful, reviewable leads** by:

1. Consuming outputs from **other pipeline stages** (JS, URLs, historical, cloud, GitHub, RRP).
2. Presenting **one operator desk** instead of scattered folders.
3. Improving path/probe intelligence **without** giant unbenchmarked wordlists.
4. Integrating Notion tips **as small, measurable contracts** — not a bulk dump into Hunter.

**Success metric:** more *useful candidates per minute of operator time*, not more empty files or more CONFIRMED noise.

---

## 2. What “information disclosure family” means here

Not only the workflow step named “Information Disclosure Scan”.

| Family member | Role |
|---------------|------|
| Path probes | `.git`, backups, configs, dir listing, error strings |
| Body classification | Prove content supports disclosure hypothesis |
| JS secrets / SI-2 / SI-4 | High-signal secret *candidates* for review |
| Source maps | Frontend debug / source exposure leads |
| GitHub recon / dorks | Passive public code & doc exposure |
| Historical pivot + validation | Archive ↔ current host/path correlation |
| Representation differential | Observational Accept/html vs json diffs |
| Cloud exposure V1 | Bucket/provider *clues* (403 ≠ vuln) |
| RRP | `SECRETS_REVIEW`, `EXPOSURE_QUEUE`, GATE honesty |
| Hunter rows from fixed-path / linkfinder | Manual follow-up only |

---

## 3. Current state (truth)

### Strong today
- JS deep + secret detectors → `SECRETS_REVIEW` (SI→Hunter **OFF** by policy).
- Historical host+path pivot (post-scope fixes).
- RRP surfaces (`GATE_0`, secrets, exposure).
- Cloud Exposure V1 (clues only).
- `classify_info_disclosure_body` available for path hits.
- `js/endpoints.txt` materialization (PR #71).

### Weak / gap
- **No unified Disclosure Desk** — operator must open many paths.
- Path probe list is **short and static**; often **0 hits** on hardened targets (EMPTY_VALID, not “stage dead”).
- **Does not feed** from JS inventory (e.g. `.map` siblings) or discovered path basenames.
- **`docs/dorking_engine.py` = IMPLEMENTED_NOT_INVOKED** on default Zero Track.
- GitHub recon **narrower** than Notion GitHub Dorking Manual.
- Notion Module 24 playbooks (app disclosure, auth-driven disclosure) **not** dedicated engines.
- Tips & Tricks pages exist in Notion; **few are wired** as versioned query/path families.

### Explicit policy (do not break)
- No auto-CONFIRMED from status code / filename / search hit alone.
- SI→Hunter stays OFF until evidence + redaction + benchmark gates pass.
- Do not enable large dork lists into Hunter.
- Do not raise resource caps to “look stronger.”
- Bulk Nuclei stays NOT_RUN.

---

## 4. Notion → code mapping (what to harvest)

| Notion source | Harvest as |
|---------------|------------|
| Module **24** + 24.2 historical | Already partially in historical scripts; desk must surface STILL_LIVE / interesting |
| 24.3 Client/JS/build | Source maps + JS secrets + endpoints desk section |
| 24.4 Application disclosure | Future: response/header/error patterns (after desk) |
| 24.5 Auth-driven disclosure | Stays with AC/IDOR engines; desk may *link* only |
| 24.6 Infra/secondary | Cloud V1 + origin notes |
| Passive Intelligence & Dorking Blueprint | Contracts for P2 dorking (provider states, scope gate) |
| GitHub Dorking Manual | **P1b** small query registry (openapi, workflows, swagger) |
| Tips: `.git` HEAD/config, source maps, Azure DevOps, etc. | Path families + GitHub query families with provenance IDs |
| Fix Control Center 2026-10-27 | This plan’s backlog order |

**Rule:** translate tips into **query_id / path_id + hypothesis + evidence type**, not copy-paste hundreds of strings into YAML.

---

## 5. Execution phases

### Phase 0 — Ops baseline (no code)

| ID | Task | Done when |
|----|------|-----------|
| 0.1 | Authorized **light** run on main ≥ `e1f710a` | Run id recorded |
| 0.2 | Open GATE_0 → SECRETS → EXPOSURE → hunter → smart_403 → cloud | Notes in ledger / Fix Control |
| 0.3 | Confirm #69/#70/#72 live (Smart403 summary, hunter non-empty when signals exist, ASN section in GATE_0) | Checklist ticked |

---

### Phase 1 — P0 Disclosure Desk (highest ROI) — **DONE**

**Intent:** one file operators open for the whole family.

| ID | Task | Status |
|----|------|--------|
| 1.1 | `scripts/build_disclosure_desk.py` | **DONE** |
| 1.2 | `triage/DISCLOSURE_DESK.md` + `meta/disclosure_desk.json` | **DONE** |
| 1.3 | Hook in `scripts/run_rrp_triage_bundle.sh` | **DONE** |
| 1.4 | Link from GATE_0 operator next | **DONE** |

**Desk sections (order):**
1. Executive counts (hits vs empty-but-ran)
2. Secrets / SI-4 high (capped list + path to full SECRETS_REVIEW)
3. Path probe positives (git/backup/config/dir/error) + classification if present
4. Source maps
5. GitHub recon kept
6. Historical: STILL_LIVE sample + validation outcome histogram
7. Cloud: content_supported / listing / strong provider_clue only
8. LinkFinder API_ROUTE sample (from normalized jsonl / endpoints.txt)
9. Pointers: EXPOSURE_QUEUE, hunter_queue, full artifact paths

**Non-goals for Phase 1:** new active probes, dorking enablement, CONFIRMED.

---

### Phase 2 — P1a Stage-derived path intelligence — **DONE**

**Code:** `scripts/run_derived_disclosure_probes.py` (budget default 80), workflow after Info Disclosure, desk section 8.

**Intent:** custom probe list from **this run’s** surface, not SecLists megadump.

| ID | Task | Source stage | Probe idea | Guard |
|----|------|--------------|------------|-------|
| 2.1 | JS → source map candidates | `js/files.txt` | `url + ".map"` | Cap N hosts/files; body classifier |
| 2.2 | Path → backup siblings | URLs / linkfinder paths | `.bak`, `~`, `.old`, `.orig` on basename | Cap; HTML shell ≠ hit |
| 2.3 | Record in `info_disclosure/derived_probes.jsonl` | — | status, class, evidence ref | Never CONFIRMED |
| 2.4 | Feed positives into Desk + optional hunter LEAD | Desk builder | — | LEAD max |

**Budget:** hard max probes (e.g. ≤ 80 derived) so CI stays bounded.

---

### Phase 3 — P1b Bounded GitHub passive slice

**Intent:** Notion GitHub Dorking Manual → **small** registry.

| ID | Task | Notes |
|----|------|-------|
| 3.1 | Query registry YAML/JSON: `query_id`, hypothesis, provider=github | org/domain from target profile only |
| 3.2 | Provider status enum | `NOT_CONFIGURED \| ERROR \| RATE_LIMIT \| PARTIAL \| COMPLETED_ZERO \| COMPLETED_WITH_CANDIDATES` |
| 3.3 | Scope gate on repo/html_url before keep | Fail closed |
| 3.4 | Redacted snippets only in artifacts | No raw secret values in logs |
| 3.5 | Desk section + optional EXPOSURE lines | SI→Hunter still OFF |

Starter families (examples only): `openapi` / `swagger.json` / `path:.github/workflows` / `graphql schema` — **authorized org/domain only**.

---

### Phase 4 — P2 Dorking engine (after 1–3)

| ID | Task |
|----|------|
| 4.1 | Implement Blueprint contracts on `docs/dorking_engine.py` (or successor under `pipeline/`) |
| 4.2 | Offline fixtures: true/false positives, 429, empty success vs error-as-empty |
| 4.3 | Optional workflow only (`dorking-optional.yml`); **not** default Hunter input |
| 4.4 | Benchmark metrics before any default enable |

---

### Phase 5 — Later / optional (not blocking)

| ID | Item |
|----|------|
| 5.1 | App-response disclosure heuristics (24.4) as separate bounded engine |
| 5.2 | Stronger export validation beyond first 3 JSONL lines |
| 5.3 | Historical phase label when validation all BLOCKED |
| 5.4 | Tighten cloud `name_guess` active probe policy |

---

## 6. Acceptance criteria (per phase)

### Phase 1
- [ ] Desk file always written (even if all sections empty-with-ran)
- [ ] At least one fixture test: secrets-only run still produces desk section
- [ ] No new CONFIRMED emissions

### Phase 2
- [ ] Derived probes ≤ budget
- [ ] HTML soft-404 not counted as backup hit
- [ ] `.map` hit classified with body/map heuristic

### Phase 3
- [ ] Missing GitHub token → `NOT_CONFIGURED`, not silent zero
- [ ] Out-of-scope repo URLs dropped
- [ ] Rate limit recorded as `RATE_LIMIT`

### Phase 4
- [ ] Blueprint checklist items for provider states + scope
- [ ] No direct Hunter promotion from raw search hits

---

## 7. Implementation order (checklist for agents)

```text
[ ] 0.1–0.3 light run verification
[ ] 1.1–1.4 Disclosure Desk
[ ] 2.1–2.4 derived paths from JS/URLs
[ ] 3.1–3.5 GitHub registry slice
[ ] 4.x dorking contracts (only if 1–3 stable)
```

Do **not** start Phase 4 before Phase 1 is merged and verified.

---

## 8. Out of scope (explicit)

- Enabling SI→Hunter
- Restoring bulk Nuclei
- Raising ASN/live/port caps
- Google HTML scraping as default
- Automatic `.git` dump/exploit chains in CI
- Importing full Orwa wordlist packs without benchmark
- Claiming “empty path files ⇒ target secure” when GATE is FUNNEL_OK

---

## 9. Chat conclusions captured

1. ID is a **family**, not one step.  
2. Notion knowledge >> wired pipeline; gap is **integration + desk**, not lack of tips.  
3. JS secrets + historical + RRP are the strongest members today.  
4. Path stage “empty” on Superdrug-class targets is often **honest EMPTY_VALID**.  
5. Custom wordlists must be **run-derived** from other stages.  
6. Full Tips translation in one PR is rejected; **phased contracts** only.  
7. Fix Control Center + this doc are the memory for execution after chat ends.

---

*End of plan.*
