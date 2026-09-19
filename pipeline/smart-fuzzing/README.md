# Smart Fuzzing — V1 (Target-Aware Adaptive Hunter Engine)

V1 only. No AI, no adaptive re-fuzz loop, no exploitation — see the
project's Target-Aware Adaptive Hunter Engine spec for V2 (application
learning / pattern mining) and V3 (evidence graph / signal ranking / AI
triage / hunter queue). This module replaces the "download common.txt"
step in `.github/workflows/zero-track-hunter.yml`'s Content Discovery
Fuzzing job with a target-specific wordlist, without changing the
fuzzing engine itself (still `ffuf`).

## What it does

```
Existing recon (this run's own output)
        │
        ▼
target_profile.py   → smart-fuzzing/target_profile.json
        │              (technologies, hosts, api/swagger/graphql presence)
        ▼
vocabulary.py        → smart-fuzzing/vocabulary.json
        │              (words the app itself exposes, with source tracking:
        │               js / url / swagger / graphql / admin / parameter)
        ▼
wolf_selector.py     → smart-fuzzing/wolf_selected.txt
        │              (a small, curated slice of Wolf: generic
        │               admin/backup/api lists + technology-matched lists
        │               + one parameter list, NOT all of Wolf)
        ▼
wordlist_builder.py  → smart-fuzzing/target_wordlist.txt
        │              (Wolf selection + vocabulary + evidence-based
        │               variants, capped per hunting_mode)
        ▼
baseline.py           → smart-fuzzing/baseline.json
        │              (how each host responds to a nonexistent path —
        │               SPA-fallback detection, per the Intigriti
        │               "Web fuzzing for hackers" methodology)
        ▼
ffuf (existing engine, same flags as before, new wordlist)
        │              → smart-fuzzing/ffuf_raw/<host>.json
        ▼
response_diff.py     → smart-fuzzing/response_diffs.json
                        smart-fuzzing/interesting.txt
                        (SPA_FALLBACK / DUPLICATE / NOISE / INTERESTING /
                         UNKNOWN — never "vulnerability found")
```

`scripts/smart_fuzzing.sh` orchestrates all of the above and is called
from the workflow. If anything here fails or produces an empty wordlist,
the workflow step falls back to the original SecLists `common.txt`
behavior — this module is additive, not a hard replacement.

## Why

See the project's Target-Aware Adaptive Hunter Engine spec: don't ask
"what's in a generic wordlist", ask "what has this application already
told us is plausible". A word seen in the app's own JS + API + as a live
parameter is stronger evidence than any generic wordlist entry.

## Running it standalone

```bash
RD=results/999-example.com TARGET=example.com HUNTING_MODE=normal \
  bash scripts/smart_fuzzing.sh
```

Requires the same recon artifacts the main workflow already produces
under `$RD` (`live/`, `js/`, `js_deep/`, `urls/`, `targeted/`). Missing
inputs degrade gracefully — e.g. no `arjun_params.txt` just means no
parameter-sourced vocabulary, not a crash.

## Known limitation (V1, by design)

ffuf's `-of json` output does not include response bodies, so
`response_diff.py` sets `"body_available": false` on every hit and never
fabricates a body-similarity/SPA-fingerprint claim from data it doesn't
have. Classification in V1 is status + content-length + content-type
only. Real body fingerprinting/similarity is a Response Intelligence
phase item (see the project's Access-Control Intelligence spec:
`response_intelligence/normalize.py`, `fingerprint.py`, `similarity.py`),
not implemented yet.

## Fixed bugs (with regression tests in `tests/test_response_diff.py`)

- **Baseline cross-host matching (`or True`)**: the original host-lookup
  had a condition that was always true, so with more than one host in a
  run, a candidate could be scored against the wrong host's baseline.
  Confirmed on a real run (superdrug.com) where this produced 21/21 hits
  classified INTERESTING — statistically implausible and a clear sign of
  broken matching. Fixed by exact `scheme://host` matching against ffuf's
  own `config.url`; no match falls through to `UNKNOWN`, never a guess.
- **Repeated block-page spam**: the same run showed ~20 different
  `_admin*` path variants all returning a near-identical WAF/403 page,
  each counted as its own "INTERESTING" lead. Fixed with a per-host,
  tolerance-based (±15 bytes) duplicate detector — a `DUPLICATE`
  classification, not a full WAF-fingerprint module (that's later).
  On the same real run this took INTERESTING from 21 down to 3.
- **`vocabulary.json` unbounded growth**: on the same real run this file
  reached 4MB / ~59k words, 99.7% of them backed by a single source
  (weak evidence) — the opposite of the "Signal Quality" goal. Root
  cause: asset/cache-busting hashes in JS/URL filenames (e.g.
  `ca19626ec727b5901735ca91a33b36`) were being tokenized as if they were
  application vocabulary. Fixed with a hex/high-digit-ratio filter plus a
  hard `MAX_VOCAB_SIZE=2000` cap regardless of input size. On the same
  real run this took the file from 4MB/58,932 words to 140KB/2,000.

## Known limitation NOT fixed yet: build-tool noise

The hex-hash filter above catches random hashes, but does not
distinguish real application vocabulary (`invoice`, `merchant`) from
legitimate-looking words that come from front-end build tooling rather
than the application itself (e.g. Next.js's own `webpack`, `chunks`,
`polyfills`, `framework`, `manifest`). On the superdrug.com run these
dominated the top of the vocabulary list post-fix. This needs a
technology-aware stopword list (e.g. "if technologies includes Next.js,
also exclude known Next.js build-artifact tokens") — not implemented,
tracked here rather than silently left unmentioned.

- **`baseline.py` silent host-count/probe-failure truncation**: the same
  real run had 34 hosts in `live.txt` but only 16 entries in
  `baseline.json`, with no explanation anywhere. Cause: a `--max-hosts`
  default of 20 silently truncated the list, and hosts whose probes
  failed were dropped with no log line either. Both fed directly into
  `response_diff.py`'s `UNKNOWN` classifications with no way to trace
  back why. Fixed: `--max-hosts` default raised to 200 (a safety
  ceiling, not a routine limiter — the input file is already the
  pipeline's own priority-filtered host list), and both truncation and
  per-host probe failures are now logged explicitly.

- **`live/tech.json` was always empty — two separate causes, both fixed**:
  1. `scripts/live_host_probing.sh`'s `probe_hosts()` call that produces
     `tech.json` was missing httpx's `-td` (tech-detect) flag entirely,
     so even a successful httpx run had no `tech` field to write.
     **This also silently disabled the existing pipeline's own Nuclei
     tech-aware pass** (`zero-track-hunter.yml`'s `-as` scan is gated on
     `[ -s "$RD/live/tech.json" ]`) and WordPress detection — not just
     this module. Fixed by adding `-td` to that httpx call.
  2. Separately, `target_profile.py` was reading `tech.json` with a
     plain `json.load()`, but httpx's `-json` output is NDJSON (one
     object per line, one per host) — the same format the pipeline's
     own `jq` calls elsewhere already assume. A multi-line file throws
     on `json.load()` and was being silently swallowed by a bare
     `except`, so `technologies` always came back `[]` regardless of
     what httpx found. Fixed with a proper per-line NDJSON reader.

  Note: a pre-existing, separately-documented issue in this pipeline
  (proxychains/Tor httpx calls occasionally returning 0 bytes for an
  entire target — see `zero-track-hunter.yml`'s own "DIRECT first"
  comment) can still leave `tech.json` empty on some runs even with both
  of the above fixed. That's a Tor-reliability issue, not this bug.

- [x] Reads existing recon, builds `target_profile.json`
- [x] Extracts vocabulary with source tracking
- [x] Selects a small, relevant slice of Wolf (not all of it)
- [x] Builds a capped, evidence-based target-specific wordlist
- [x] Establishes a baseline per host (SPA-fallback aware)
- [x] Runs the existing `ffuf` engine against the new wordlist
- [x] Classifies hits against baseline (SPA_FALLBACK / NOISE / INTERESTING)
- [x] Falls back to `common.txt` behavior on any failure
- [ ] Measure signal quality on a real authorized target before starting V2

## Explicitly out of scope for V1

- Adaptive re-fuzzing / new-candidate generation from interesting responses
- Pattern mining (`/api/v1/{resource}` inference)
- Evidence graph, signal scoring/ranking
- AI triage, `hunter_queue.md`
- Any autonomous exploitation
