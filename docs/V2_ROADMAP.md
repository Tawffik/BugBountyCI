# V2 Roadmap — everything intentionally deferred from V1

V1 (this session's work) is closed. This document exists so nothing
from the original Target-Aware Adaptive Hunter Engine / Master
Engineering Prompt specs gets lost or forgotten just because it wasn't
built yet. Anyone (including a future Claude session with no memory of
this one) should be able to read this and know exactly what's left and
in what order to build it.

## What V1 actually delivered (Definition of Done — met)

- **Smart Fuzzing V1** (`pipeline/smart-fuzzing/`): target profiling,
  application vocabulary extraction, Wolf knowledge selection,
  target-specific wordlist building, baseline/response-diff
  intelligence. 5 real bugs found and fixed against real recon data
  (superdrug.com).
- **Detection Engine Framework** (`pipeline/detection/engine.py`): the
  common `Candidate`/`Evidence`/`DetectionEngine` interface every
  engine below implements, with an enforced 5-label classification
  system (NOISE/LOW_SIGNAL/LEAD/HIGH_SIGNAL/CONFIRMED) and a
  continue-on-error orchestrator.
- **Access-Control Engine** (`access_control_engine.py`): safe path
  mutations against 401/403 endpoints, replay-verified before
  HIGH_SIGNAL, with a real Cloudflare-edge-error (52x) false-positive
  fix found on a real run.
- **Open Redirect Engine** (`open_redirect_engine.py`): evidence-based
  candidates from vocabulary, internal-vs-external Location
  distinction, canary-domain verification.
- **IDOR/BOLA object enumeration** (upgraded the pre-existing
  "AI Agent Phase 5" step rather than duplicating it): DIRECT-first
  fallback added, honest "enumeration, not confirmed bypass" framing
  already present and preserved.
- **Unified Hunter Queue** (`hunter_queue_builder.py`): merges all of
  the above plus smart-fuzzing's own findings into one prioritized
  `detection/hunter_queue.md`.
- **41+ tests** across `pipeline/smart-fuzzing/tests/` and
  `pipeline/detection/tests/`, several run against real fixture data
  from an actual superdrug.com scan, not synthetic-only.

## Known open item from V1 (not a new idea — unfinished diagnosis)

- **`live/tech.json` still empty on real runs.** Confirmed root cause
  category (not yet the exact fix): `httpx` exits 0 with zero bytes of
  output against this specific target on both Tor and DIRECT, while
  `curl` succeeds fine against the same hosts — almost certainly a
  TLS-fingerprint-level rejection by Cloudflare specific to Go's HTTP
  client, not a flag/crash/timeout issue (all three were ruled out with
  evidence). `-v` was added to `scripts/live_host_probing.sh` to
  capture the real per-host error on the next run — **read
  `logs/httpx.log`'s new output first**, then fix with evidence, don't
  guess again.

---

## Deferred ideas, in priority order

Ordered by the same reasoning applied throughout V1: real bug-bounty
value first, foundational/scaffolding work only when a concrete engine
actually needs it — not "build the framework piece because the spec
listed it."

### Priority 1 — high real-world value, natural next engines

1. **API Security Engine / Parameter Intelligence** (spec section 31,
   53). Build an `endpoint -> relevant parameters` map from
   Swagger/OpenAPI/GraphQL/observed URLs (`js/swagger.txt`,
   `js/graphql.txt`, `targeted/arjun_params.txt` already exist in
   recon). This is genuinely foundational — the IDOR engine and any
   future SSRF/injection engine both get much more precise candidates
   once this exists, instead of each engine parsing `urls/all.txt`
   independently the way `idor_engine.py`'s logic and
   `open_redirect_engine.py` currently do.
2. **SSRF Engine** (spec section 26). High severity, and
   `vocabulary.json` already surfaces the right words (`url`, `webhook`,
   `callback`, `proxy`, `import`). Verification needs an OOB adapter
   (Interactsh) — see Priority 3.
3. **True multi-session IDOR/BOLA** — upgrading the current
   enumeration-only check into a real cross-user authorization test
   requires a second authenticated session/account. This needs a
   product decision (does the workflow have/accept two sets of
   credentials?) before any code, not just an engineering task.

### Priority 2 — moderate value, straightforward to build on existing infrastructure

4. **XSS Engine** wrapping Dalfox as an adapter (spec section 25) —
   Dalfox already runs in this pipeline as a standalone tool; the value
   here is candidate selection (reflection + context detection) before
   invoking it, not replacing it.
5. **Subdomain Takeover Engine** wrapping Subzy (spec section 43) —
   similarly, Subzy already runs; the gap is correlating its raw output
   into the same Evidence/classification system as everything else,
   not new detection logic.
6. **CORS Engine** (spec section 37) — `cors/` output already exists in
   recon; needs the same evidence-based, replay-verified treatment the
   other engines got, distinguishing "ACAO changed" from "sensitive data
   actually became cross-origin accessible."

### Priority 3 — infrastructure needed by Priority 1/2, build only when actually blocking

7. **Adapters** (`pipeline/detection/adapters/` — currently empty).
   Needed once SSRF (Interactsh for OOB) or a real SQLi engine
   (SQLMap escalation) actually gets built — don't build adapter
   scaffolding speculatively before an engine needs it.
8. **Signal Ranker** (spec section 27/49) — a shared scoring function
   across all engines' evidence, so the Hunter Queue can rank within a
   priority tier, not just between tiers (current `hunter_queue.md`
   only sorts by classification, not a finer score). Worth building
   once there are enough real findings across enough engines that
   within-tier ordering actually matters.

### Priority 4 — genuinely large scope, defer until several Priority 1-2 engines exist

9. **SQLi, SSTI, LFI/Path Traversal, GraphQL Intelligence, File Upload,
   Auth/JWT/OAuth, Cache Intelligence, WebSocket, Webhook, Cloud
   Exposure, Secret Intelligence, JS/Prototype Pollution engines**
   (spec sections 24, 27-30, 34-44). Each is a real, valuable engine on
   its own, but building all of them before validating the pattern on
   3-4 more targets (beyond superdrug.com) would repeat the exact
   mistake the project's own spec warns against: "don't build 20
   one-off scripts, understand the target first." Pick the next one
   based on what real bug-bounty programs are actually in scope when
   this is picked back up.
10. **Attack Surface Graph** (spec section 22) and **Evidence Graph**
    (spec section 28) — connecting host↔endpoint↔parameter↔JS↔evidence
    into an actual graph structure. High conceptual value for AI
    correlation later, but premature before there are enough engines
    producing evidence to actually need graph-level correlation instead
    of the current flat evidence lists.
11. **AI Triage Layer** (spec section 48) and **Feedback Loop**
    (`feedback.jsonl`, spec section 50) — AI correlation/hypothesis
    generation over the Evidence Graph, and researcher-classification
    feedback improving future ranking. Explicitly last in the original
    spec's own ordering (section 55: "Phase 14, Phase 15") — this
    project's existing `ai/` folder already has separate AI triage
    logic for other parts of the pipeline; integrating that with the
    Detection Engine Framework's evidence is the actual task here, not
    building a new AI layer from scratch.

---

## How to pick this back up

1. Read `pipeline/detection/README.md` and `pipeline/smart-fuzzing/README.md`
   first — both document what exists, what's fixed, and what's a known
   limitation.
2. Run the full test suite (`pipeline/smart-fuzzing/tests/*.py` +
   `pipeline/detection/tests/test_*.py`) before touching anything, to
   confirm the starting point is still green.
3. **Check for existing functionality before building anything new** —
   this session built a full IDOR engine once before realizing a better
   one already existed elsewhere in the workflow (`AI Agent Phase 5`).
   Search `.github/workflows/zero-track-hunter.yml` and every
   subfolder under `results/<any-run>/` for a category that might
   already be handled before writing a new engine for it.
4. Apply the same checklist every fix/engine in this session followed:
   - no unbounded output (always a cap)
   - no silent failure (always log what got skipped/dropped and why)
   - test against real data before trusting synthetic tests alone
   - watch for CDN/edge infrastructure errors (52x) being misread as
     application signals
   - DIRECT-first for anything that diffs a response against a
     baseline (Tor is fine for initial discovery, risky for comparison)
   - one engine/fix per commit, with the real evidence that motivated
     it in the commit message
