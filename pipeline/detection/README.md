# Detection Engine Framework (skeleton)

**Status: framework only, validated by a toy engine. Zero real
vulnerability engines exist yet (no SQLi/XSS/SSRF/etc.). Do not treat
this as "Access-Control Intelligence" or any specific engine — it's the
common shape every future engine will subclass.**

## Why this exists before any real engine

The project's own spec (section 23/54 of the Master Engineering Prompt)
warns against building 20 engines' worth of one-off scripts. This
framework is the interface every future engine (SQLi, XSS, SSRF, Access
Control, ...) will implement, so they share:

- the same Candidate/Evidence data shapes
- the same 5-label classification system (NOISE/LOW_SIGNAL/LEAD/
  HIGH_SIGNAL/CONFIRMED) — enforced at the `Evidence` dataclass level,
  so an engine literally cannot invent `"VULNERABILITY_FOUND"`
- the same fail-safe orchestration: one broken engine never stops the
  others, mirroring the `continue-on-error` pattern used everywhere
  else in this pipeline's workflow and scripts
- the same candidate cap (`max_candidates`), so no future engine can
  reproduce the vocabulary.py 4MB/59k-word blowout from a different
  code path

## What's actually here

```
pipeline/detection/
├── engine.py            Candidate, Evidence, DetectionEngine, run_engine(), run_engines()
├── adapters/             empty — for external-tool adapters (SQLMap, Dalfox,
│                         Nuclei, Interactsh...) once a real engine needs one
├── packs/                empty — for detection-pack config (see spec section 46)
└── tests/
    ├── toy_engine.py      a deliberately fake, non-functional "open redirect"
    │                      engine used ONLY to exercise the framework
    └── test_framework.py  6 tests proving the interface works end-to-end
```

## The interface (what a real engine implements)

```python
class DetectionEngine:
    def prerequisites(self, target_profile) -> bool: ...
    def generate_candidates(self, target_profile, vocabulary) -> list[Candidate]: ...
    def detect(self, candidate) -> Evidence | None: ...
    def adapter(self, candidate, detect_evidence) -> Evidence | None: ...  # optional
    def verify(self, evidence) -> Evidence: ...                            # optional
```

Only `generate_candidates()` and `detect()` are required — `adapter()`
and `verify()` default to no-ops, so a minimal engine can be written and
run end-to-end without external tools or replay logic yet.

## Running the tests

```bash
python3 pipeline/detection/tests/test_framework.py
```

## What this is explicitly NOT yet

- No real engines (SQLi/XSS/SSRF/Access-Control/...) — those come after
  this framework is validated against a real one, per the project's own
  phased implementation order
- No adapters (SQLMap/Dalfox/Nuclei/Interactsh) — `adapters/` is empty
- No wiring into `zero-track-hunter.yml` or `smart_fuzzing.sh` — this is
  not called from anywhere in the actual pipeline yet
- No Attack Surface Graph / Evidence Graph / Signal Ranker — those are
  separate, later pieces per the project's own architecture

## Next step (not done in this commit)

Build ONE real engine on top of this (the project's own recommended
order puts Access-Control Intelligence first, since Response
Intelligence/baseline work already exists in `pipeline/smart-fuzzing/`
to build on) and validate it against real recon data before adding a
second engine.
