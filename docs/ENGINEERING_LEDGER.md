---

## FINAL GATE — 2026-10-08 — V1→V4 finish audit (cross-repo)

### Gate status (evidence-based)

| Gate | Status | Evidence |
|---|---|---|
| **V1 reliability / truthfulness** | **SATISFIED** | ERROR≠EMPTY, OOB_NOT_SEEN≠CONFIRMED, PARTIAL≠CLEAN; #134/#135 live |
| **V2 export / Hunter / observations** | **SATISFIED** | recon_export.v1, Hunter 27 after scheme-only filter LIVE #135 |
| **V3 intelligence loops** | **SATISFIED** | Historical, Representation, Smart Fuzz honesty, LinkFinder API — live closed earlier |
| **V4 integration / handoff / freeze** | **SATISFIED (offline E2E)** | BBCI `sra_handoff.json` → SRA `372ff70` ClosedLoop offline episode |

### Cross-repo path
```
BBCI producer (meta/sra_handoff.json)
  → SRA normalize_bbci_artifact (sra_handoff.v1)
  → ReconResultAdapter
  → OpportunityEngine
  → ClosedLoopRunner (offline lab scenario)
```
SRA HEAD: `372ff70`  
Tests: `test_sra_handoff_adapt.py` + offline E2E suite green offline.

### Explicitly NOT claimed
- Live SRA research episode against capital.com HTTP
- SI-1…SI-9 mature secret intelligence product (SI-0 audit only; not required for V1 product finish)
- Sengi runner restoration (environment)
- Nuclei error_rate ≈0 (remains DEGRADED/PARTIAL — truthful)

### Protected contracts
Unchanged and verified by latest live #135 + offline SRA path.

### PROJECT_COMPLETE criteria
Approved BBCI V1 product finish line (recon→evidence→Hunter→export→adapter handoff) is met with offline cross-repo E2E proof. Remaining items are optional expansion or environment, not open REQUIRED product dependencies.

**Declaration:** PROJECT_COMPLETE for approved BugBountyCI V1 finish line + offline adapter handoff.

---

## CYCLE — 2026-10-08 — Cross-repo BBCI → SRA handoff OFFLINE VERIFIED

### Problem
BBCI-side `meta/sra_handoff.json` alone does not prove SRA consumption.

### SRA work (security-research-agent)
- HEAD: `6880654`
- `bbci_contract.normalize_bbci_artifact` recognizes `bugbountyci.sra_handoff.v1`
- Endpoint **host** preserved on normalize
- Fixture: `examples/fixtures/bbci/capital_sra_handoff.json` (from #135 capital)
- Tests: `tests/test_sra_handoff_adapt.py` (2 passed)
- `run_offline_sra_handoff_adapt()` — adapt stage, no live HTTP

### Evidence
```
primary_host=capital.com
n_endpoints>=5
contract_ok=True
stages.adaptation=True
```

### Status
**OFFLINE VERIFIED** (cross-repo contract + ReconResultAdapter)
NOT live research episode (ClosedLoop) against capital — would be SRA runtime, not required to prove producer→adapter path.
NOT PROJECT_COMPLETE (full finish line still includes broader product gates).

### BBCI side
Handoff projector remains CLOSED (deterministic). No multi-hour re-run required for this contract proof.

### Next READY (auto-select by finish-line impact)
Evaluate remaining: SI track vs full offline ClosedLoop on handoff vs documentation freeze — only if still required by Master Architecture finish line.

---

## CYCLE — 2026-10-08 — SRA handoff projection (finish-line dependency)

### Context after #135
Scheme-only Hunter filter LIVE VERIFIED. No multi-hour reconfirm.
Highest finish-line gap: BBCI `recon_export.v1` is producer-shaped; SRA
`ReconResultAdapter` expects consumer fixture shape (`primary_host`, `endpoints[]`).

### Implementation (BBCI only — boundary preserved)
- `scripts/export_sra_handoff.py` → `meta/sra_handoff.json` (`bugbountyci.sra_handoff.v1`)
- Workflow emits handoff after pipeline exports
- `recon_export` artifact index declares `sra_handoff`
- Tests: `tests/test_sra_handoff.py`

### Offline evidence (#135 capital results)
- primary_host=capital.com
- endpoints=27 (endpoints.jsonl + linkfinder API_ROUTE)
- minimal contract_ok=True

### Status
IMPLEMENTED + TESTED + ARTIFACT REPLAY
NOT full E2E with security-research-agent process (that remains SRA-side offline_bbci_episode).
This closes the **BBCI-side handoff artifact** gap only.

### Next READY
1. Optional: SRA-side offline episode against `meta/sra_handoff.json` (other repo)
2. SI-1 only if chosen over handoff/E2E
3. Do not re-run long Zero Track solely for this deterministic projector

---

## CYCLE — 2026-10-08 — scheme-only Hunter filter LIVE VERIFIED (#135)

### Run
- **ID:** 37693581179
- **SHA:** `b3564ec` (includes `9b3aa3a` filter)
- **Target:** capital.com · light · **success** · ~171 min

### Expected vs actual
| Check | Expected | Actual |
|---|---|---|
| scheme-only REDIRECTED in `historical_validations.jsonl` | present (evidence retained) | **40 REDIRECTED**, all scheme-only |
| `historical_pivot` in Hunter | **0** for scheme-only | **0** |
| Useful engines retained | SSRF / API / smart-fuzz if surface allows | **27** = 1 ssrf HIGH_SIGNAL + 25 linkfinder_api + 1 smart-fuzz |
| OOB honesty | NOT_SEEN if oob empty | OOB_NOT_SEEN ×1 · oob_findings empty |
| Export index | nuclei_track + linkfinder + smart metrics | present |

### Status
**FIXED+LIVE VERIFIED** — scheme-only historical redirects excluded from Hunter; evidence kept in validations artifact.

### Protected contracts
No regression observed on OOB / API→Hunter / export / DEGRADED health (Arjun ERROR + Nuclei PARTIAL truthful).

### Next READY (dependency sweep)
Not PROJECT_COMPLETE. Highest remaining finish-line directions (pick by evidence, no feature invent):
1. Human consumption of remaining Hunter (auth/trading API + SSRF differential)
2. SI-1 only if Secret Intelligence chosen as next track
3. ReconResultAdapter handoff verification (outside pure BBCI scanner work)
4. Environment: Sengi quota when available

---

## CYCLE — 2026-10-08 — LIVE VERIFY scheme-only Hunter filter (IN PROGRESS)

### Reconcile
- HEAD at dispatch: `b3564ec`
- Code contains `_is_scheme_only_redirect` + ENGINE_TIER (`9b3aa3a`)
- #134 was last success on `5b8941d` (pre-filter code for hunter builder)

### Action
Dispatched light authorized Zero Track on **capital.com**:
- **Run:** https://github.com/Tawffik/BugBountyCI/actions/runs/37693581179
- **Purpose:** LIVE prove Hunter omits scheme-only historical REDIRECTED; retains SSRF/API/smart-fuzz signals
- **Expected:** historical_pivot count in hunter_queue ≈ 0 for scheme-only; linkfinder_api + ssrf present if surface allows

### Status
LIVE VERIFICATION **IN PROGRESS** — not yet VERIFIED

### Independent offline
Unit tests for scheme-only + OOB/API hunter contracts executed in agent environment during wait.

### Next after harvest
Compare expected vs actual → close LIVE VERIFICATION PENDING or fix → dependency sweep (not auto SI-1)

---

## CYCLE — 2026-10-08 — Track A Review of 28 Hunter candidates (NO additional code fix)

### Artifact
Replay of `hunter_queue_builder` @ `9b3aa3a` on #134 results (`37660905816` / capital.com).
Queue path: `detection/hunter_queue.md` → **28 entries**.

### Classification summary
| Class | Count | Notes |
|---|---:|---|
| A Actionable research surface | ~14 | auth/trading/user/ums API paths |
| B Useful + needs manual validation | ~6 | SSRF×2 (differential only), api-website roots/sync, some auth |
| C Low value | ~6 | bare `/api`, country.*, sentiment, cmp/test-cmp, smart-fuzz IP:8443 |
| D Derivative | 1 pair | SSRF http vs https same `page` param — treat as one research thread |
| E Noise / should not be in Hunter | 0 | after scheme-only filter |

**HIGH_SIGNAL ≠ CONFIRMED.** Both SSRF show OOB probe language / OOB_NOT_SEEN; `oob_findings.txt` empty.

### Provenance
- Run id in header when `GITHUB_RUN_ID` set (replay: 37660905816)
- linkfinder_api: source JS hash present; **20/25 targets are host-relative** — human must bind host
- historical scheme-only: excluded from queue; retained in `historical_validations.jsonl`
- smart-fuzz: short evidence line (status delta only)

### Decision
**NO FIX** — no further code change from this review.
Remaining limitations are researcher-consumable, not queue-breaking noise.

**LIVE VERIFICATION PENDING** for `9b3aa3a` scheme-only exclusion (deterministic offline only so far).

**SI-1 not started.**

### Next READY (single)
Optional: one light authorized live run to confirm Hunter omits scheme-only historical and retains SSRF/API — **or** human research on the ~14–20 actionable API/auth candidates. Not automatic SI-1.

# ENGINEERING LEDGER — BugBountyCI / Zero Track

> **Read this file first, before touching any code.** This is not a
> changelog. It is the project's memory, because chat sessions don't
> persist and this repo is the only thing that does. Every fix,
> without exception, gets logged here with its evidence — not just
> "what changed" but "why this was broken, how we know it's fixed, and
> what it depends on." If you fix something and don't update this
> file, the next session will re-discover the same bug from scratch,
> or worse, "fix" something that was already fixed and break it again.

---

## CYCLE — 2026-10-08 — Track A Hunter usefulness (scheme-only historical)

### Decision (reconcile first)
- **Not** auto SI-1 (secret track not higher-value than Hunter product surface)
- **Not** reopen OOB/API/Representation/SmartFuzz
- **Track A:** #134 Hunter had 40/68 entries = scheme-only http→https REDIRECTED (same host/path)

### Problem
Hunter product surface diluted: research priority list dominated by low-value scheme upgrades.

### Evidence
`info_disclosure/historical_validations.jsonl` on #134: 40 REDIRECTED, all scheme_only.

### Fix
`9b3aa3a` `hunter_queue_builder.py`:
- skip scheme-only REDIRECTED in queue (artifact retained)
- ENGINE_TIER: ssrf/API above historical
- header: Run id + engine counts

### Offline replay (#134 artifacts)
Before: 68 entries (40 historical)
After: **28** (2 ssrf HIGH_SIGNAL + 25 linkfinder_api + 1 smart-fuzz)

### Tests
`tests/test_hunter_scheme_only_redirect.py`

### Status
IMPLEMENTED + TESTED + ARTIFACT REPLAY VERIFIED
LIVE VERIFICATION PENDING (optional light run — behavior deterministic from validations.jsonl)

### Next READY
- Optional live light to pack new hunter semantics in CI artifact
- SI-1 only if secret track chosen deliberately
- Human review of remaining 28 capital candidates

---

## CYCLE — 2026-10-08 — #134 live + SI-0 Secret Intelligence Audit

### HEAD
`5b8941d` (OOB honesty + LinkFinder API Hunter seeds; #134 ran on this SHA)

### LIVE — capital.com #134 / `37660905816` / success ~173m
| Contract | Actual |
|---|---|
| OOB honesty | `OOB_NOT_SEEN`×2; probe FIRED; zero "callback registered"; `oob_findings.txt` empty |
| linkfinder_api → Hunter | **25** INTERESTING |
| Hunter total | **68** (40 historical + 25 API + 2 ssrf + 1 smart-fuzz) |
| LinkFinder | API~30 · WEB~897 · STATIC~1789 |
| Smart Fuzz | DIFFS_GENERATED · findings=1 · post_ac=4 |
| nuclei_track | PARTIAL ~45.8% errors — not CLEAN |
| recon_export index | nuclei_track + linkfinder_summary + smart_fuzzing_metrics present |

**Status:** OOB + API-Hunter gaps **CLOSED / LIVE VERIFIED**. Do not reopen without regression.

### SI-0 — Secret detector audit (repo + #134 artifacts) — COMPLETE

**Do not build a new secret scanner.** Behavior is known from evidence:

| Detector | Artifact | #134 capital.com | Hunter? | Notes |
|---|---|---:|---|---|
| SecretFinder | `js_deep/secretfinder_secrets.txt` | 108 lines | No | Heavy FP pattern classes: possible_Creds 39, Heroku API KEY 35 (UUID-shaped), authorization_api 25, twilio_account_sid 7 |
| Gitleaks | `js_deep/gitleaks_findings.json` | 1 | No | `generic-api-key` on JS `MODAL_KEYS` identifier — **false positive** |
| TruffleHog | `js_deep/trufflehog_findings.jsonl` | 0 | No | Empty this run |
| Mantra | `js_deep/mantra_findings.txt` | 8 | No | Mix of empty tokens / public-looking captcha / noise |
| Cariddi | `js_deep/cariddi_findings.txt` | 100 | No | Mostly **URL discovery** (robots/sitemap), not secret intelligence |

**Root gaps (evidence-backed, not implemented this cycle):**
1. No canonical secret candidate schema / dedupe across detectors
2. No FP resistance for UUID/Heroku/generic-api-key on JS identifiers
3. No Hunter promotion path (correct for now — would flood queue)
4. No phase/health file for secret sub-pipeline (counts only in funnel text)
5. Cariddi output is not "secrets" — naming/consumer mismatch

**SI-0 exit condition met:** exact current behavior known from repository + #134 artifacts.

**Next READY (only if continuing secret track):** SI-1 deterministic sanitized fixtures + baseline metrics (TP/FP/dup/provenance) — *not* a new detector.

### Protected contracts (still hold)
ERROR≠EMPTY · PARTIAL≠CLEAN · OOB_NOT_SEEN≠OOB_CONFIRMED · HIGH_SIGNAL≠CONFIRMED · INTERESTING≠VULNERABILITY · LinkFinder raw≠API · Historical/Representation closed unless regression

### Environment
Sengi quota exhausted historically → ubuntu-latest interim; not an architecture rewrite.

### Anti-loop decision
Reliability/intelligence honesty slices for OOB+API are verified. Secret path is audited (SI-0). Further secret work must start at SI-1 benchmark, not SI-7 queue flood.

---

## 0. The one thing to hold onto

**This is not a tool collection. It is one pipeline whose only job is:
turn a domain name into a short list of things a human should actually
look at, with as little noise as possible, on ANY target — without a
person having to configure it per-target.**

Every phase below exists to serve that sentence. If a phase doesn't
make the final list shorter, more accurate, or more target-specific,
it isn't done yet, however clean its own code is. "It has tests" and
"it produces a good result for a bug bounty" are different claims —
this project has repeatedly (see §2) shipped the first and mistaken it
for the second.

**Governing document:** the Notion page "BugBountyCI — Master
Architecture, Audit & Evolution Roadmap"
(https://app.notion.com/p/3e0dac31e880817d93d3cd5e4b92a62f). Its source
of truth hierarchy (§65): actual repo code > current run artifacts >
that Notion page > this file / docs/V2_ROADMAP.md / docs/
PROJECT_FULL_STATE.txt > general ideas. Read the Notion page's §61
execution order before starting new work — it puts "add a new engine"
LAST (step 9), after reliability/canonical-observations/target-model/
candidate-intelligence are solid, and this project has repeatedly
jumped ahead of that order (see §3).

---

## 1. Architecture map — what feeds what, and why each link exists

```
Recon (subdomains, live hosts, URLs, JS, params)
        │
        ├─→ target_profile.json ──────────┐
        ├─→ vocabulary.json (word-level)  │  Smart Fuzzing V1
        ├─→ predicted_paths.json ─────────┤  (target_profile.py → wolf_selector.py
        │   (pattern_predictor.py:        │   → wordlist_builder.py → ffuf →
        │    this target's OWN grammar,   │   response_diff.py → interesting.txt)
        │    not a static wordlist)       │
        └─→ parameter_intelligence.json ──┼──→ Detection Engines
            (real endpoint→param map)     │    (access_control_engine.py,
                                          │     open_redirect_engine.py,
                                          │     ssrf_engine.py — all on the
                                          │     same Detection Engine Framework,
                                          │     engine.py: candidates → detect
                                          │     → adapter (OOB) → verify (replay))
                                          │
                                          ▼
                              detection/engine_results.json
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    ▼                     ▼                     ▼
        hunter_queue_builder.py   metrics_builder.py      OOB Check (Interactsh)
        → hunter_queue.md         → metrics.json          → oob_findings.txt
        (ONE ranked file,         (Signal Precision —      (real callback
         the actual deliverable)  the only number that      confirmation for
                                  should be trusted to       any engine that
                                  say "did this get          registered a
                                  better or worse")          label)
```

**Why parameter_intelligence.json exists and matters:** it's the
single real endpoint→parameter map for THIS target. SSRF Engine reads
it instead of re-deriving its own weaker view of urls/all.txt — this
is the difference between "guess a URL might take ?url=" and "this
target's own recon already proved it does." Any future engine that
needs parameters (a real IDOR engine, an LFI engine) should read this
file too, not build a fourth parser.

**Why pattern_predictor.py's output feeds wordlist_builder.py and
nothing else yet:** it was built to be engine-agnostic (emits
`predicted_paths.json`, not tied to fuzzing), but access-control and
open-redirect still use their OLD static candidate sources
(PATH_MUTATIONS, a fixed param-name list) — see §4 item 2, this is the
single most requested-and-not-yet-done piece of "stop treating engines
like separate tools."

**Why the status/health layer (`meta/phases/*.json`) sits underneath
everything:** every phase, in bash (`pipeline_lib.sh`) or Python
(`engine.py`'s `write_phase_status`), writes the SAME status vocabulary
(`ok|empty|error|skipped_starved|skipped`) so one future health report
can read every phase the same way, regardless of which language wrote
it or which run it was. Before this (through 2026-09-26), a script
exiting 0 meant nothing — see bug #16 below.

---

## 2. Bug ledger — every real bug found, with evidence, chronological

Rule for this table: a row only gets added when there was a **specific
piece of evidence** (a number, a log line, an empty file that should
have had content) — not "this seems better now." "Status" is honest:
`FIXED+VERIFIED` means a live GitHub Actions run confirmed it after the
fix; `FIXED (unverified)` means the fix shipped but no live run has
confirmed it yet — check that before assuming it's actually closed.

| # | Component | Symptom (the evidence) | Root cause | Fix commit | Status |
|---|---|---|---|---|---|
| 1 | `zero-track-hunter.yml` | `Invalid workflow file`: one `run:` block's `${{ }}` expression exceeded GitHub's 21,000-char limit | Bash+Python heredoc with repeated `${{ env.X }}` inline instead of real env vars | `7c22115` | FIXED+VERIFIED |
| 2 | naabu/subfinder/assetfinder | Steps could hang indefinitely (no timeout) | Missing `timeout` wrapper on long-running recon tools | `56d3c87`, `5d10ace` | FIXED+VERIFIED |
| 3 | `response_diff.py` | 21/21 ffuf hits classified INTERESTING — statistically impossible if classification worked | `or True` in the baseline-matching condition — every host compared against every baseline | `cfa2d2b` | FIXED+VERIFIED (21→3 real INTERESTING + 18 DUPLICATE on the same real superdrug.com data) |
| 4 | `vocabulary.py` | 58,932 words / 4MB, 99.7% single-source | No filter for hex/hash-looking asset filenames (cache-busting build hashes) | `5248926` | FIXED+VERIFIED (→ 2,000 words / 140KB) |
| 5 | `baseline.py` | 34 hosts in live.txt, only ~16-20 in baseline.json, no warning | Hardcoded `--max-hosts=20` silently truncating, no logging | `9d8ea36` | FIXED+VERIFIED |
| 6 | `live_host_probing.sh` + `target_profile.py` | `tech.json` = 0 bytes on every run, every target | `httpx` call missing `-td` (tech-detect) flag entirely, AND separately the JSON parser expected single-object JSON but httpx writes NDJSON | `9d8ea36` | FIXED (this specific cause), but see #6 below — the file was STILL empty afterward for a different reason |
| 6b | same | `tech.json` still 0 bytes after fixing #6 | Cloudflare rejects httpx's Go TLS fingerprint on some targets — confirmed via `curl` succeeding on the exact same URL where `httpx` returned 0 bytes on both Tor AND direct | `57d6617` (real curl fallback added) | FIXED+VERIFIED (curl-based tech detector, `Cloudflare` correctly detected on a target httpx fully failed on) |
| 7 | Open Redirect / Access-Control (design, not yet a bug) | — | Tor-only by default, no fallback | `b40812f`, `fd8b449` | FIXED+VERIFIED (DIRECT-first is now the rule everywhere network calls happen) |
| 8 | `access_control_engine.py` | 4/4 access-control candidates HIGH_SIGNAL on a real run | Cloudflare edge errors (520-527, e.g. 525 SSL handshake failed) classified as a legitimate differential signal | `28984d7` | FIXED+VERIFIED (4→0 HIGH_SIGNAL false, 2 genuine LEAD) |
| 9 | `engine.py` | Access-Control's findings disappeared once Open Redirect ran | `engine_results.json` written with `mode="w"` (overwrite) instead of merge, called separately by each engine's own CLI script | `b03caf0` | FIXED+VERIFIED |
| 10 | IDOR (whole engine) | Built a new IDOR engine from scratch | Didn't check first — a better, already-working IDOR step (`AI Agent Phase 5`) already existed in the workflow | `477c9bb` | FIXED (deleted the duplicate, upgraded the existing one instead) — **the single most expensive process lesson in this ledger; see §5** |
| 11 | `live_host_probing.sh` | `[FTL] verbose flag is incompatible with silent flag` — every single httpx call failing with exit=1 | A `-v` flag added for diagnosis (session before) was never removed, and directly conflicts with the pre-existing `-silent` flag | `02457b5` | FIXED+VERIFIED (confirmed zero FTL errors on a live okx.com run) |
| 12 | `zero-track-hunter.yml` (dalfox/arjun auth) | Dalfox XSS findings = 0 on **every single run reviewed** (#96-#99), regardless of target | `AUTH_ARGS` built once with Arjun's flag syntax (`--headers`, real) and reused for Dalfox, which only accepts `-H` — confirmed via `logs/dalfox.log`: `Error: unknown flag: --headers` on every run where `AUTH_COOKIE` was set | `fc384db` | FIXED (unverified — needs a run with AUTH_COOKIE set to confirm Dalfox actually finds anything now that it can start) |
| 13 | `pattern_predictor.py` | 300 predictions, 1 of 9 unique action words was `ohuxaq` — an analytics-beacon URL segment, not a real word | `_looks_like_word` only rejected ALL-CAPS random tokens (`isupper()`) | `9d8ea36`-era fix inside `42803f0`'s own dev cycle (see #14 for the harder follow-up) | FIXED, but incomplete — see #14 |
| 14 | `pattern_predictor.py` | On a LATER real run, `igibxoc` (mixed-case, e.g. from `.../IgIbxOc/...`) polluted ~300 predictions — every single resource on the site got a fake `/{id}/igibxoc` candidate | The #13 fix only checked `.isupper()` — a mixed-case random token isn't all-uppercase, so it passed straight through | `fc384db` | FIXED+VERIFIED (re-ran the predictor against the exact real run's full URL list: `igibxoc` gone, all 9 remaining action words real) |
| 15 | `ssrf_engine.py` | 2 candidates classified HIGH_SIGNAL on the first live production run | Detection matched on a single generic substring (`"metadata"` or `"169.254.169.254"`) in the response body — real proof it was false: `ai_agent/oob_findings.txt` came back EMPTY, meaning neither server ever actually attempted the fetch | `0a67732` | FIXED+VERIFIED (same run's candidates: 60/60 correctly NOISE after the fix) |
| 16 | `smart_fuzzing.sh` + all 3 `run_*.py` detection scripts | A script could crash outright and still report success — no way to distinguish "ran, found nothing" from "actually failed" | Unconditional `exit 0` (bash) / no structured status output (Python) | `6961ac6` | FIXED+VERIFIED (`meta/phases/{smart_fuzzing,access_control,open_redirect,ssrf}.json` all present and accurate on a live run) |
| 17 | `wordlist_builder.py` | On a real run's actual `target_wordlist.txt`: Wolf = 220/300 lines (73%), `vocabulary.json` (this target's own evidence) = 5/2000 available words (0.25%) | Wolf's ~4000-entry output added to the candidate set uncapped, AND the ranking function put "not in Wolf" ahead of vocabulary words — generic beat target-specific, backwards | `970dac2` | FIXED (unverified — needs a live run to confirm the real proportions; local re-run against the exact data that exposed the bug showed Wolf 220→100, vocabulary 5→119) |
| 18 | Workflow step ordering | SSRF Engine's findings wouldn't appear in that same run's own `hunter_queue.md`/`metrics.json` | New step was inserted right before "OOB Check" — but AFTER "Hunter Queue Builder" and "Metrics Baseline" already read `engine_results.json` for that run | `401b09d` (caught and fixed in the same change, before merge) | FIXED+VERIFIED (real run confirms SSRF entries rank #1-2 in `hunter_queue.md`) |
| 19 | `live_host_probing.sh` | 221 candidate subdomains, DNS resolved: 0 — pipeline ran entirely starved | `dnsx` returning 0 with no fallback | `b6c34c4` | FIXED+VERIFIED (75/114 resolved via `dig`/`getent` fallback on the confirming run) |
| 20 | `live_host_probing.sh` | httpx found only ~2-14 live hosts when DNS resolved 75 | Recovery/seeding logic only ran when `live.txt` was completely EMPTY, not when it was merely sparse | `11ba302` | FIXED (unverified per this ledger — check next run's `live_hosts` count against `dns_resolve`'s `resolved=` count) |
| 21 | Content Discovery `common.txt` fallback (Gap D) | Smart-fuzzing EMPTY_VALID (`status=empty` in phase JSON) still triggered SecLists `common.txt`, undoing target-aware selection | Consumer only checked `! -s fuzzing/discovered.txt` and ignored `meta/phases/smart_fuzzing.json` | (this commit) | FIXED (unit-tested; live verification pending next Actions run) |

**Not yet in this table:** the pre-2026-09-13 commit history (the
"chore: stage ... / fix(#N)" era, ~150+ commits) has its own real fixes
(scope fail-closed, secret redaction before LLM calls, VHost SNI,
IDOR/GraphQL soft-classification) that predate this ledger and haven't
been individually re-verified against current code. If you're touching
`scripts/` files from that era, check `git log --follow <file>` before
assuming a fix from that period is still intact — this ledger's
`FIXED+VERIFIED` claims only cover what's listed above.

---

## 3. Open gaps — named, not vague, ordered by real priority

Numbering matches the Notion master doc's own gap list (§51) where
applicable, so cross-referencing stays possible.

| Gap | What's actually wrong | Why it matters more than a new engine |
|---|---|---|
| **D** | ~~common.txt fallback ignored phase status~~ **CLOSED** — see bug #21 / Gap D evidence | Consumer now uses `fallback_gate.py` |
| **E** | `response_diff.py` doesn't store the actual response body — length/status/content-type only | Every "SPA fallback" or "identical content" claim is inferred, never directly checked |
| **F** | Response classification is still coarse (status/length/content-type) | No `WAF_BLOCK` / `SPA_CATCHALL` / `AUTH_REQUIRED` / `SERVER_ERROR` / `REAL_CONTENT` split — a differential result can't yet distinguish "found a WAF" from "found content" |
| **I** | ~~Access-Control and Open-Redirect run BEFORE parameter_intelligence.json~~ **CLOSED** — param intel runs after Content Discovery / before AC+OR; OpenRedirectEngine consumes the map (fallback to vocabulary remains) | See Gap I evidence below |
| **K** | No explicit lower bound on what counts as evidence for WAF/header/origin-based checks | A bare status-code change can still read as a signal in some paths |
| **L** | "Open scope" mode (no `scope.txt`) continues silently with a warning | Should require an explicit `AUTHORIZED_OPEN_SCAN=true`-style acknowledgment, not an implicit default |
| **new** | Nuclei error rate has been stuck at 42-45% across every run reviewed (#96-#99) and has never been investigated, only reported | Directly limits Nuclei's own coverage; nobody has looked at WHY yet |
| **new** | `Arjun`/`Corsy` findings have been 0 on every run reviewed | Unlike Dalfox (bug #12, confirmed broken), no root cause confirmed yet — could be genuinely finding nothing, or silently failing like Dalfox was; unverified either way |
| **new** | Collected URL count swings wildly run to run on the same target (37,207 → 5,010 → 1,641 → 97,361) | Almost certainly external (Wayback/gau API instability), but never confirmed — and it directly determines how much data `pattern_predictor.py`/`parameter_intelligence.py` have to work with |

---

## 4. How phases actually serve each other (the "why", not just the "what")

1. **DNS/Live/URL gates exist so everything downstream fails LOUD, not
   quiet.** Bug #19 (DNS collapse to 0) is why these gates exist at
   all — before them, a starved run looked identical to a healthy one.
2. **parameter_intelligence.json should be the single param source for
   every engine that needs one — it currently isn't.** SSRF reads it;
   Access-Control and Open-Redirect still don't (open_redirect_engine.py
   parses vocabulary.json at the word level, access_control_engine.py
   uses a fixed mutation list unrelated to parameters at all). This is
   the highest-value "old thing to fix" left, because it's the same
   shape of fix that already worked for SSRF.
3. **pattern_predictor.py's output (predicted_paths.json) is currently
   single-purpose (feeds wordlist_builder.py only), but was designed
   engine-agnostic on purpose.** The same "resource_seen_in/
   action_seen_in" evidence structure could generate access-control
   candidates (predicted admin-shaped paths) and open-redirect
   candidates (predicted param names from the target's own URL
   grammar, not a fixed list) — this was the ORIGINAL ask that led to
   building pattern_predictor.py in the first place, and hasn't been
   finished.
4. **Signal Precision (metrics.json) is the only number that should
   ever be used to claim "this got better."** Every other measure (test
   count, lines of code, number of engines) has been shown in this
   ledger to be a bad proxy for that — see bug #13/#14 and #15, all of
   which had 100% passing tests at the time they were live false
   positives.
5. **The Hunter Queue is the actual product.** Everything above it is
   infrastructure. If a change doesn't make `hunter_queue.md` shorter,
   more accurate, or catch something on a NEW target it wouldn't have
   caught before, it isn't the highest-priority thing to build next,
   regardless of how clean it is in isolation.

---

## 5. Process rules (earned the hard way — see the bug/lesson each one cites)

1. **Grep before building.** Bug #10 (duplicate IDOR engine) and the
   SSRF OOB adapter (this project nearly hand-rolled Interactsh's
   crypto protocol before discovering a working integration already
   existed in the same workflow file) both cost a full rebuild. Before
   writing a new engine, script, or verification mechanism: `grep -rn`
   the workflow and every `scripts/`/`pipeline/` file for the
   capability you're about to build.
2. **A new step must run BEFORE whatever consumes its output, not just
   before the workflow ends.** Bug #18. Passing tests do not catch
   this — only reading the actual step order in the YAML does.
3. **"All tests pass" is not "verified."** Bugs #3, #8, #13, #14, #15
   each had passing unit tests while being live false positives on
   real data. A fix is `FIXED+VERIFIED` in §2 only after a real run's
   artifact (not a mock) confirms it.
4. **When a fix touches a shared resource used by multiple sources
   (Wolf + vocabulary + predictions; Arjun + Dalfox's shared
   AUTH_ARGS), check EVERY consumer, not just the one you're looking
   at.** Bug #12 and #17 are both "one shared thing, two different
   real needs, nobody checked the second one."
5. **Update THIS FILE in the same commit/session as the fix.** Not
   after. Not "later." A fix without a ledger entry is functionally
   invisible to the next session.

---


### Gap D evidence (2026-09-30)

- **Wrong:** Content Discovery Fuzzing fell back to SecLists `common.txt` whenever `fuzzing/discovered.txt` was empty, including when smart-fuzzing wrote `meta/phases/smart_fuzzing.json` with `"status":"empty"` (EMPTY_VALID).
- **Change:** `pipeline/smart-fuzzing/fallback_gate.py` decides allow/skip; workflow calls it before common.txt; statuses `empty`/`ok` → skip; `error`/`skipped*`/`cancelled`/missing/malformed → allow.
- **Tests:** `pipeline/smart-fuzzing/tests/test_fallback_gate.py` (12 cases) — all passed.
- **YAML:** minimal consumer change only in Content Discovery Fuzzing step (no job/trigger/order redesign).
- **Limitation:** FIXED until a live Actions run log shows `skipping common.txt fallback (Gap D)` or `gate=error` as appropriate; mark FIXED+VERIFIED after that.



### Gap I evidence (2026-10-01)

- **Wrong:** `parameter_intelligence.py` ran only inside the SSRF step
  (late in the workflow). Access-Control and Open-Redirect therefore
  never saw real endpoint→parameter pairs and used weaker candidate
  sources (response_diffs path mutations / vocabulary host guesses).
- **Change:**
  1. Workflow: new "Parameter Intelligence" step immediately after
     Content Discovery Fuzzing and before Access-Control / Open-Redirect.
  2. Removed the late generation call from the SSRF step (SSRF still
     consumes the file).
  3. `OpenRedirectEngine` accepts `parameter_map`; prefers real
     endpoints that already expose redirect-like params; falls back to
     pre-Gap-I vocabulary path when the map is empty.
  4. `run_open_redirect.py` loads `detection/parameter_intelligence.json`
     and injects it (same pattern as SSRF).
- **Tests:** existing open-redirect suite + 2 new cases
  (`test_parameter_intelligence_prefers_real_endpoints`,
  `test_parameter_intelligence_empty_falls_back_to_vocabulary`); full
  `pipeline/detection/tests` = 107 passed.
- **Limitation:** FIXED (unit-tested). Live FIXED+VERIFIED only after a
  zero-track-hunter run shows Parameter Intelligence before AC/OR and
  open-redirect candidates sourced from parameter_intelligence when the
  map is non-empty. Access-Control still does not yet expand candidates
  from the map (path-mutation engine); map is available on disk for a
  follow-up if triage shows need.



### Port scan empty-with-live-hosts (2026-10-01 study)

- **Observation:** Runs #100 (capital.com) and #101 (superdrug.com) both had
  live hosts (126 / 98) and `live/ports.txt` line count **0**.
- **Root cause (evidence):** `logs/naabu.log` on both runs:
  `FTL Could not run enumeration: no valid ipv4 or ipv6 targets were found`
  (repeated). Port Scanning step used **Tor-only** `proxychains4 naabu -l`
  on hostnames (`all_subs.txt`). Classification: **TOOL/NETWORK ERROR**,
  not TRUE EMPTY and not "port discovery absent from workflow".
- **Why it mattered:** Downstream treated empty ports as no non-standard
  services; health report did not flag ports as ERROR; enrich-from-ports
  path never ran.
- **Change (same session):**
  1. Prefer `subdomains/resolved.txt` as naabu input when non-empty.
  2. **DIRECT-first** naabu, then Tor fallback (same pattern as ASN CIDR path).
  3. Phase status `meta/phases/port_scan.json` with OK | EMPTY | ERROR | NOT_RUN
     so ERROR ≠ EMPTY.
- **Verification:** unit/YAML only until next zero-track completes with
  non-empty ports or explicit ERROR without silent empty. Mark
  FIXED+VERIFIED after live log shows DIRECT attempt and truthful status.
- **Related open:** Nuclei ~42.8% error rate (health report #101) remains
  open investigation — not fixed here. Arjun 0 / Corsy 0 on #101 may be
  true empty or silent failure; capital #100 had 6 arjun lines — target-
  dependent, not uniformly zero.


### Port scan classification gaps after 28dd077 (2026-10-02)

28dd077 fixed the **primary root cause** (Tor-only hostname path) but left
classification holes:

1. **Exit codes discarded** (`|| true`) — timeout (124) with ports=0 could
   classify as EMPTY instead of ERROR.
2. **FTL matched against shared `logs/naabu.log`** — ASN path also appends
   there; false ERROR/EMPTY risk.
3. Tor fallback still keyed on `ports==0` (acceptable) but status did not
   distinguish DIRECT failure vs legitimate empty without FTL text.

**Follow-up fix:** dedicated `logs/naabu_portscan.log`, preserve DIRECT_RC/TOR_RC,
classify ERROR on non-zero exit or FTL in portscan-only log; ports>0 → OK;
else clean exit 0 → EMPTY. Synthetic tests: `scripts/tests/test_port_scan_status.sh`.

**Live:** #103 on 28dd077 still in_progress / no post-fix artifacts at time of
write → **LIVE VERIFICATION PENDING** (not VERIFIED).


## 6. What "next" actually means right now

Per §3, the highest-leverage NOT-YET-DONE items, in order:
1. ~~Gap D~~ **DONE**: `fallback_gate.py` + Content Discovery step.
2. ~~Gap I~~ **DONE** (this session): parameter_intelligence before AC/OR;
   OpenRedirectEngine consumes the map. Access-Control still primarily
   uses response_diffs (path mutations); map is available for future AC
   enrichment.
3. ~~Port scan Tor-only empty~~ **FIXED (unverified live)** this session —
   DIRECT-first + resolved input + phase status ERROR≠EMPTY.
4. Nuclei's 42-45% error rate (confirmed 42.8% on #101 health report) —
   tool is running; high request errors — incomplete coverage, not clean.
5. Arjun/Corsy: not uniformly zero (#100 capital had 6 arjun lines; #101
   superdrug 0) — investigate before assuming silent failure.
6. Manual triage of existing hunter_queue items still valuable (takeovers,
   CORS-CRITICAL, oEmbed SSRF candidate).

**Do not start a new engine (XSS, SQLi, IDOR-multi-session, etc.)
before these.** That was the mistake §61 of the Notion doc warns about
by name, and this ledger's own bug list is the evidence for why.


### Final repair — Port Scan follow-up (2026-10-02)

**#103 evidence (SHA 28dd077, nuva.finance):** phase=`ERROR`, ports=0, FTL on
DIRECT+Tor with valid `resolved.txt` (6 hosts). Classification honest;
discovery still blocked. Health report did not flag port ERROR.

**cd536a1:** (1) dnsx `-a -resp-only` pre-resolve → feed IPs to naabu;
(2) if still 0, one DIRECT pass without `-exclude-cdn`; (3) Pipeline Health
prints explicit warning when `port_scan` phase is ERROR.

**Status:** FIXED — LIVE VERIFICATION PENDING (need ZT on cd536a1+).
Synthetic classification tests still pass (1491f1f suite).



### Campaign — Port discovery VERIFIED + Nuclei input (2026-10-02)

**#106** (SHA 963ba62, nuva.finance): Port scan **OK** — 8 IPs via dig/getent/live,
14 open host:port pairs, phase OK, health "Port scan OK". Closes discovery FTL
seen on #100–#104 for this path.

**Nuclei #106:** error_rate 41.6% (hosts=12, ~32k errors / ~78k requests). Log:
unresponsive "no address found" / port closed on http + IP targets. Health
already DEGRADED. Follow-up commit filters nuclei input to hostname HTTPS and
writes meta/phases/nuclei.json (PARTIAL when error_rate≥40).



### #108 harvest + Nuclei Tor gate (2026-10-02)

**#108** (7279d32, nuva.finance): ports=26 OK; nuclei input 6 hosts; DNS
pre-check kept 6; light skipped pass 2/3; **Tor fallback still ran** on
findings=0 → step timeout 40m; error_rate 52.1%; phase **PARTIAL**
synthesized by health (`synthesized_after_timeout=true`).

**Fix:** skip Tor nuclei fallback in light; in normal require DIRECT
coverage pct>=80 and error_rate<35 before Tor.

**Limitation:** high nuclei error_rate on hosts that flake mid-scan
("no address found" / i/o timeout) remains target/network behavior;
must stay PARTIAL/DEGRADED, not CLEAN.


### #109 LIVE VERIFIED — Nuclei Tor gate (2026-10-02)

**#109** (8e237ee): Port OK ports=29. Nuclei: skip pass 2/3 + **skip Tor**
confirmed in logs; step completed success ~32m (no 40m timeout);
phase PARTIAL written in-step (findings=0, error_rate=52.3, coverage 67%).
Health DEGRADED correctly.

**Limitation retained:** ~52% nuclei errors on nuva flaky hosts mid-scan
("no address found" / i/o timeout) — not treated as clean.

**Next:** Arjun DIRECT-first + phase ERROR on AttributeError (#108 evidence).


### #110 Arjun LIVE VERIFIED + export v1 (2026-10-02)

**#110** (987d88c, nuva.finance): port_scan OK ports=15; arjun phase=PARTIAL
params=4 with tool errors still in log (upstream AttributeError); Health flag
"Arjun phase=PARTIAL — Do not treat parameter discovery as clean." Nuclei
PARTIAL error_rate=51.8%. Smart fuzz / OR / SSRF EMPTY_VALID intact.

**Reliability foundation for critical stages considered closed** with known
limitations documented (flaky-host nuclei errors; arjun upstream bug).

**Next:** meta/engine_health.json + meta/target_profile.json written at health
step (schema v1) for stable downstream export — live verify on next run.


### #111 export LIVE VERIFIED + hosts.jsonl (2026-10-02)

**#111** (a1cfe2f): meta/engine_health.json + meta/target_profile.json present and
consistent with phases (port OK 25, arjun PARTIAL, nuclei PARTIAL 51.9%, overall
DEGRADED). Protected fixes intact.

**Next:** meta/hosts.jsonl additive host surface model from live/verified/ports/resolved.


### #112 hosts.jsonl LIVE VERIFIED (2026-10-02)

**#112** (057aa91): hosts.jsonl=20 structured hosts; ports=19 OK; arjun PARTIAL;
nuclei PARTIAL 52.3%; export engine_health+target_profile intact. No regression.

**Next:** meta/observations.jsonl LEAD/SIGNAL/HEALTH rows from arjun/nuclei/smart_fuzz/phases.


### Surface model urls/endpoints/parameters (2026-10-03)

Additive export in `scripts/write_pipeline_exports.py`:
- meta/urls.jsonl (cap 5000 from urls/all.txt)
- meta/endpoints.jsonl from detection/parameter_intelligence.json
- meta/parameters.jsonl (per-endpoint + global hints)

Does not re-parse discovery; reuses Gap I parameter intelligence artifact.
Local synthetic test passed. Live verify pending after #114 completes.


### Export vocabulary + relationships (2026-10-03)

**Code:** meta/vocabulary.json from smart-fuzzing vocabulary (schema
bugbountyci.vocabulary.v1); meta/relationships.jsonl lightweight edges
(HOST_HAS_PORT, HOST_HAS_URL, ENDPOINT_HAS_PARAMETER). Unit test
tests/test_write_pipeline_exports.py passes.

**Live:** pending after #114 harvest; tip includes surface model exports.


### #114 observations LIVE VERIFIED (2026-10-03)

**#114** (a1bcb54): write_pipeline_exports ran successfully. Port OK 13;
hosts.jsonl=18; observations.jsonl=12 (arjun LEADs + phase health);
engine_health+target_profile present. Nuclei PARTIAL 54.4%; Arjun PARTIAL.
No GA 21k regression.

**Still pending live on tip:** urls/endpoints/parameters, vocabulary,
relationships, response_clusters (#115/#116).


### #115 surface+vocab+relationships LIVE VERIFIED (2026-10-03)

**#115** (92e1885): ports=20; hosts=20; observations=10; urls=1586;
endpoints=24; parameters=42; vocabulary=1500; relationships=1037.
response_clusters pending #116.

### Tip pushed + #116 response_clusters LIVE + #117 started (2026-10-03)

**Push:** c721d1f (then d66514a docs) on main — V1–V4 tip landed.
**#116 harvest (token):** response_clusters.json schema bugbountyci.response_clusters.v1
present; clusters=0 because response_diffs.json was empty [] — truthful EMPTY,
not ERROR. Port OK 22; hosts 22; urls 838; endpoints 16; parameters 30;
vocabulary 1500; relationships 1004; observations 11; engine_health DEGRADED
(Arjun+Nuclei PARTIAL). recon_export not on #116 (pre-tip).
**#117:** workflow_dispatch on c721d1f target=nuva.finance authorized_open_scan=true
— queued then in_progress (validates Gap L + tip contracts live).

### V2 RELEASED — #118 LIVE (2026-10-03)

Run **37103828216** / admin.shopify.com / SHA a1e0d7a / success.
- recon_export.v1 schema + artifact index including ranking/outcome
- response_ranking.v2: REDIRECT=1, waf_dominated=false
- strategy_outcome.v3: useful_signals=1, recommendation=continue_target_aware
- response_clusters: 1 REDIRECT
- target_profile smart-fuzzing v2: Cloudflare, cdn_or_edge
- hunter_queue: INTERESTING entry with (REDIRECT) classification
- Arjun phase=ERROR (crash) not emptied — health DEGRADED truthful
- Port OK 3074; relationships 987 including URL_TO_RESPONSE_CLASS

### V3 tip (post-V2)
- wordlist_builder adapts wolf cap from .previous_snapshot/strategy_outcome.json when waf_rate>=0.5
- snapshot step copies strategy_outcome.json for next run
- relationships: JS_TO_API (swagger/graphql), HOST_TO_ENDPOINT
