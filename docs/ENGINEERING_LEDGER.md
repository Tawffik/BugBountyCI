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

## 6. What "next" actually means right now

Per §3, the highest-leverage NOT-YET-DONE items, in order:
1. ~~Gap D~~ **DONE**: `fallback_gate.py` + Content Discovery step.
2. ~~Gap I~~ **DONE** (this session): parameter_intelligence before AC/OR;
   OpenRedirectEngine consumes the map. Access-Control still primarily
   uses response_diffs (path mutations); map is available for future AC
   enrichment.
3. Manual triage of what's SITTING IN THE QUEUE RIGHT NOW: the 4-5
   subdomain-takeover candidates (Cargo Collective, stable across
   every run), the 8 CORS-CRITICAL findings (reflected origin +
   credentials=true, a genuinely strict check), and the WordPress
   oEmbed SSRF candidate — none of these need a line of new code, they
   need a human to open `hunter_queue.md` and verify.
4. Nuclei's 42-45% error rate and the Arjun/Corsy zero-findings pattern
   — both unconfirmed root causes, both potentially the same class of
   bug as #12 (silent tool failure hiding behind "0 findings").

**Do not start a new engine (XSS, SQLi, IDOR-multi-session, etc.)
before these.** That was the mistake §61 of the Notion doc warns about
by name, and this ledger's own bug list is the evidence for why.
