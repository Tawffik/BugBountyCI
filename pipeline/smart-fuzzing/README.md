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
                        (SPA_FALLBACK / NOISE / INTERESTING — never
                         "vulnerability found")
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

## Definition of Done (V1)

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
