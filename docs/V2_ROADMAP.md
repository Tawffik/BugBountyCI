# BugBountyCI — Roadmap & Architecture Decision Record

**Read this first if you're picking this project back up.** This file
exists so nothing from any design document ever gets lost or silently
re-decided — but "kept" does not mean "queued to build." Four master
specs have been written for this project across several sessions
(listed in §4). This document is the single reconciled source of
truth: what's actually built, what's genuinely next, and what's
recorded-but-deliberately-deferred.

---

## §1. What's actually built (verified, not aspirational)

- **Smart Fuzzing V1** (`pipeline/smart-fuzzing/`): target profiling,
  application vocabulary extraction (with source-tracking), Wolf
  knowledge selection, target-specific wordlist building,
  baseline/response-diff intelligence. 5 real bugs found and fixed
  against real recon data (superdrug.com).
- **Detection Engine Framework** (`pipeline/detection/engine.py`): the
  common `Candidate`/`Evidence`/`DetectionEngine` interface every
  engine below implements. Enforces the 5-label classification system
  (NOISE/LOW_SIGNAL/LEAD/HIGH_SIGNAL/CONFIRMED) at the dataclass level
  - an engine cannot invent its own label - plus a continue-on-error
  orchestrator so one broken engine never stops another.
- **Access-Control Engine** (`access_control_engine.py`): safe path
  mutations against 401/403 endpoints, replay-verified before
  HIGH_SIGNAL, with a real Cloudflare-edge-error (52x) false-positive
  fix found on a real run.
- **Open Redirect Engine** (`open_redirect_engine.py`): evidence-based
  candidates from vocabulary, internal-vs-external Location
  distinction, canary-domain verification.
- **IDOR/BOLA object enumeration** - the pre-existing "AI Agent Phase
  5" step was upgraded (DIRECT-first fallback added) rather than
  duplicated. Explicitly scoped as *enumeration evidence*, not a
  confirmed cross-user bypass - see §6 item 4 for what a real
  multi-session IDOR check would need.
- **Unified Hunter Queue** (`hunter_queue_builder.py`): merges
  Access-Control + Open Redirect + IDOR + smart-fuzzing's own findings
  into one prioritized `detection/hunter_queue.md`.
- **41+ tests** across `pipeline/smart-fuzzing/tests/` and
  `pipeline/detection/tests/`, several run against real fixture data
  from actual scans (superdrug.com, and later capital.com/datacamp.com
  diagnostics), not synthetic-only.

---

## §2. Known open items (live diagnosis, not yet closed)

1. **`live/tech.json` - root cause found, fix pushed, not yet
   re-verified on a real run.** `-v` had been added to `httpx` in a
   prior diagnostic commit to investigate why this file came back
   empty - that `-v` flag turned out to be fatally incompatible with
   `-silent` in this httpx version (`[FTL] verbose flag is
   incompatible with silent flag`, confirmed on capital.com and
   datacamp.com runs: 1200+ and 4170+ log lines, 100% failure). `-v`
   has been removed. **Next run should show real `technologies: [...]`
   values** - confirm before trusting anything technology-aware
   downstream (Wolf Selector's tech-specific list selection depends on
   this).
2. **`smart-fuzzing/response_diffs.json` empty on both capital.com and
   datacamp.com (25/25 `ffuf_raw/*.json` files `"results": []`) -
   cause not yet confirmed.** Two competing hypotheses: (a) `-ac`
   autocalibration correctly filtering a heavily-WAF'd target that
   returns an identical block-page signature for every candidate
   (legitimate), or (b) the same Go-binary TLS-fingerprint rejection
   class already found in httpx, now suspected in `ffuf` too. `-s`
   (silent) was removed from the `ffuf` call in
   `scripts/smart_fuzzing.sh` as a temporary diagnostic to capture
   ffuf's own `Errors: N` summary line - **read
   `logs/smart_ffuf.log`'s `[ffuf-diag]` lines on the next run before
   deciding.** Restore `-s` once this is resolved, per the lesson from
   leaving `-v` in httpx too long.

**Current instruction: do not start §6 below until both of these are
closed with evidence from a real run.**

---

## §3. Core philosophy (unchanged across all 4 specs)

Every source document, independently, converges on the same principle:

> Understand the target -> select relevant tests -> execute -> compare
> -> verify -> correlate -> prioritize -> human validation.
>
> A changed response is a **signal**, not a vulnerability. Only
> evidence - reproducibility, replay stability, endpoint-specific
> content - moves a result toward `CONFIRMED`.

This is already enforced in code, not just documentation: `Evidence`'s
classification is a closed enum, `AccessControlEngine`/
`OpenRedirectEngine` both cap a single observation at `LEAD` and only
`verify()` (replay) can promote to `HIGH_SIGNAL`. Any future engine
must follow the exact same shape - this is not a new requirement to
design, it's an existing pattern to copy.

---

## §4. Source documents - what each one actually added

Four master specs exist. Rather than treating each as its own task
list (which caused real duplication once already - see §7), this
section states plainly what each contributed and what's genuinely new
vs. restated.

| # | Document | What it actually added | Redundant with |
|---|---|---|---|
| 1 | **Master Engineering Prompt** (original) | Established the whole shape: Target Profile, Vocabulary, Wolf Selector, Response Intelligence, Detection Engine Framework, the 5-label classification, Hunter Queue, the 15-phase build order. **This is the one every later doc restates.** | - (the source) |
| 2 | **Signal-Driven Manual Playbook Intelligence** | The one genuinely distinct idea: a **Playbook layer** for manual-only techniques (WAF bypass payloads, encoding tricks, SSTI/RCE payloads) that get *recommended* when a Signal matches, never auto-executed. Its `Signal`/state machine (`OBSERVED->CANDIDATE->VALIDATED->REPORTABLE/DISCARDED`) is a finer-grained version of the classification system already built. | ~70% overlaps doc #1 |
| 3 | **Master Research, Architecture & Adaptive Security Intelligence** (the "research-heavy" spec) | Two useful, narrow additions: a **Metrics Baseline** concept (Signal Precision, Noise Rate, etc. as real numbers instead of qualitative judgment) and confirmation that httpx/tech-detection verification belongs *before* new engines (its own implementation-order item 3 - which is exactly §2 above). Everything else (12-part academic research deliverable, 15+ framework schemas, GraphQL/SOAP/gRPC/WebSocket adapters) is disproportionate to the project's current size. | ~80% overlaps doc #1 |
| 4 | **Detection Engines expansion** (the "SQLMap as adapter" doc) | Concretized the **adapter pattern**: `SQLi Engine -> SQLMap Adapter`, `XSS Engine -> Dalfox Adapter`, `Takeover Engine -> Subzy Adapter` - existing tools become execution backends behind an engine's own candidate-generation/verification logic, not standalone scanners. Also named `pipeline/detection/adapters/` explicitly (already scaffolded, empty). | Engine list overlaps doc #1 |

**Decision: none of these are "the plan" individually. §6 below is the
actual plan, synthesized from all four with duplicates removed and
re-prioritized against what this repo actually needs next.**

---

## §5. Full concept reference (kept for completeness - not a build order)

Every named engine/concept across all 4 documents, deduplicated, so a
search for "did anyone already think about X" finds it here first
before writing a new spec section for it:

**Detection engines named:** SQLi, XSS, SSRF, SSTI, LFI/Path Traversal,
XXE, CRLF, CORS, Cache Deception, HTTP Request Smuggling, File Upload,
Authentication, OAuth/OIDC, GraphQL, WebSocket, Webhook, Cloud
Exposure, Subdomain Takeover, Secrets, Information Disclosure, Business
Logic, Race Condition, Mass Assignment, API Version Differential,
Function-Level Authorization, Parameter Parser Differential.

**Infrastructure concepts named:** Target Profile, Application
Vocabulary Engine, Wolf Selector, Attack Surface Graph, Evidence Graph,
Response Intelligence layer (normalize/fingerprint/similarity/
SPA-detector/WAF-detector), Detection Packs, Tool Adapter Layer, Signal
Ranker, Playbook Matcher + Playbook model, Manual Investigation Queue,
Feedback Loop (`feedback.jsonl`), Adaptive Engine (learns new
candidates from a discovered response within the same run), AI Agent
Loop (typed actions: `discover_endpoint`, `analyze_api`,
`run_detection_engine`, etc.), Metrics Baseline, Identity Graph
(auth/JWT/session/MFA), Business Flow state-machine modeling.

None of these are scheduled. This is a reference index, not a backlog.

---

## §6. The actual plan (reconciled priority order)

Real bug-bounty value first; foundational/scaffolding work only when a
concrete engine actually needs it - never "build the framework piece
because a spec listed it." This is the order to actually work in.

### Priority 0 - blocking (must close before anything below)

0. **Close §2's two open diagnostics with evidence from a real run.**
   Nothing technology-aware or fuzzing-dependent can be trusted until
   these are resolved.

### Priority 1 - high real-world value, natural next steps

1. **Metrics Baseline** (new, from doc #3 - see §4). Cheap, mechanical:
   each engine's `EngineRunResult` already has the counts needed.
   Write `detection/metrics.json` per run: candidates/requests/evidence
   counts, classification breakdown, **Signal Precision** =
   (LEAD+HIGH_SIGNAL+CONFIRMED)/candidates tested. This single number
   would have caught the Cloudflare-525 false-positive bug and the
   ffuf-zero-results anomaly as an automatic regression instead of
   requiring a manual data dive each time. Do this **after** Priority 0
   closes, so the first baseline isn't measuring a known-broken run.
2. **API Security Engine / Parameter Intelligence** (doc #1, doc #4).
   Build an `endpoint -> relevant parameters` map from
   Swagger/OpenAPI/GraphQL/observed URLs (`js/swagger.txt`,
   `js/graphql.txt`, `targeted/arjun_params.txt` already exist in
   recon). Genuinely foundational - IDOR and any future SSRF/injection
   engine get far more precise candidates once this exists, instead of
   each engine parsing `urls/all.txt` independently the way
   `open_redirect_engine.py` currently does.
3. **SSRF Engine** (doc #1, doc #4). High severity; `vocabulary.json`
   already surfaces the right words (`url`, `webhook`, `callback`,
   `proxy`, `import`). Verification needs an OOB adapter (Interactsh)
   - see Priority 3.
4. **True multi-session IDOR/BOLA** - upgrading the current
   enumeration-only check into a real cross-user authorization test
   requires a second authenticated session/account. **This needs a
   product decision (does the workflow have/accept two sets of
   credentials?) before any code** - not an engineering task.

### Priority 2 - moderate value, straightforward given existing infrastructure

5. **XSS Engine wrapping Dalfox as an adapter** (doc #1, doc #4).
   Dalfox already runs standalone in this pipeline; the value is
   candidate selection (reflection + context detection) before
   invoking it, not replacing it.
6. **Subdomain Takeover Engine wrapping Subzy** (doc #1, doc #4). Subzy
   already runs; the gap is correlating its raw output into the same
   Evidence/classification system as everything else.
7. **CORS Engine** (doc #1, doc #4). `cors/` output already exists in
   recon; needs the same evidence-based, replay-verified treatment the
   other engines got - distinguishing "ACAO changed" from "sensitive
   data actually became cross-origin accessible."

### Priority 3 - infrastructure needed by Priority 1/2, build only when actually blocking

8. **Adapters** (`pipeline/detection/adapters/` - scaffolded, empty).
   Needed once SSRF (Interactsh) or a real SQLi engine (SQLMap
   escalation) actually gets built. Don't build adapter scaffolding
   speculatively before an engine needs it.
9. **Signal Ranker** (doc #1). A shared scoring function across
   engines' evidence so `hunter_queue.md` can rank *within* a priority
   tier, not just between tiers. Worth building once enough real
   findings across enough engines exist that within-tier ordering
   actually matters.
10. **Playbook layer** (doc #2's genuine contribution - see §4).
    Minimum viable pieces, in order: (a) a static Playbook data file
    per playbook - start with just Path-Normalization/403-Bypass for
    Access-Control and IDOR/BOLA for the enumeration engine, not all
    ~30 from the spec; (b) a Playbook Matcher - a small extension of
    `hunter_queue_builder.py`, not a new subsystem; (c) a Tip
    classification pass over whatever Tips/notes source already exists
    in this repo (check before assuming one needs to be created); (d)
    reuse `hunter_queue.md` itself as the Manual Investigation Queue
    with a `status` field added, rather than a separate file/database.

### Priority 4 - genuinely large scope, defer until several Priority 1-2 items exist

11. **SQLi, SSTI, LFI/Path Traversal, GraphQL Intelligence, File
    Upload, Auth/JWT/OAuth, Cache Intelligence, WebSocket, Webhook,
    Cloud Exposure, Secret Intelligence, JS/Prototype Pollution
    engines** (see §5 for the full list). Each is a real, valuable
    engine on its own, but building all of them before validating the
    pattern on 3-4 more real targets would repeat the exact mistake
    every one of the 4 source specs independently warns against:
    "don't build 20 one-off scripts before understanding the target."
12. **Attack Surface Graph + Evidence Graph** (doc #1, doc #3).
    Connecting host-endpoint-parameter-JS-evidence into an actual
    graph structure. High conceptual value for AI correlation later,
    premature before there are enough engines producing evidence to
    need graph-level correlation instead of the current flat evidence
    lists.
13. **AI Agent Loop + Feedback Loop** (doc #1, doc #3, doc #2's `LEARN`
    stage). AI correlation/hypothesis generation over the Evidence
    Graph, typed actions (`discover_endpoint`/`run_detection_engine`/
    etc.), and researcher-classification feedback improving future
    ranking. Explicitly last in every source document's own ordering.
    This project's existing `ai/` folder already has separate AI
    triage logic elsewhere in the pipeline - integrating that with the
    Detection Engine Framework's evidence is the actual task, not
    building a new AI layer from scratch.
14. **Deep research deliverable** (doc #3's 12-part academic/
    benchmark-methodology ask). Not scheduled. Revisit only if the
    project reaches a size where that level of formal documentation is
    actually load-bearing, not before.

---

## §7. Process lessons (apply these, don't just read them)

- **Check for existing functionality before building anything new.**
  A full IDOR engine was built once before discovering a better one
  already existed elsewhere in the workflow (`AI Agent Phase 5`) -
  search `.github/workflows/zero-track-hunter.yml` and every subfolder
  under `results/<any-run>/` before writing a new engine.
- **A temporary diagnostic flag left in permanently becomes a second
  bug.** `-v` added to `httpx` to diagnose the empty-`tech.json` issue
  turned out to itself be the cause (incompatible with `-silent`).
  Applied the same care removing `-s` from `ffuf` in §2 item 2 - treat
  it as temporary until resolved with evidence, then revert.
- **No unbounded output** - always a cap (`vocabulary.py`'s
  4MB->2000-word incident).
- **No silent failure** - always log what got skipped/dropped and why.
- **Test against real data before trusting synthetic tests alone.**
- **Watch for CDN/edge infrastructure errors (52x) being misread as
  application signals** (the Cloudflare-525 false-positive fix).
- **DIRECT-first for anything that diffs a response against a
  baseline** - Tor is fine for initial discovery, risky for comparison
  (a WAF treating Tor differently than DIRECT can fabricate or mask a
  signal).
- **One engine/fix per commit**, with the real evidence that motivated
  it in the commit message.
- **A new master spec is not automatically "the plan."** Read it, state
  honestly what's genuinely new vs. restated (§4's table is the
  template), and only change priority order if it changes a real
  decision - not just because it's more recent.

---

## §8. How to pick this back up

1. Read `pipeline/detection/README.md` and `pipeline/smart-fuzzing/README.md`
   - both document what exists, what's fixed, and what's a known
   limitation at the file level.
2. Run the full test suite (`pipeline/smart-fuzzing/tests/*.py` +
   `pipeline/detection/tests/test_*.py`) before touching anything, to
   confirm the starting point is still green.
3. Check §2 - are the open diagnostics closed yet? If not, that's the
   actual next step, not §6.
4. If a new design document shows up, read §4 and §7's last bullet
   before doing anything with it.
