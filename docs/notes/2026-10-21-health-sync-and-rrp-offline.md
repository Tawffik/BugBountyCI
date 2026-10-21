# 2026-10-21 — Health JSON/MD sync + RRP offline proof

## Defect (run #167)

`meta/phases/github_recon.json` was written as invalid JSON due to shell quoting:

```text
echo "{"phase":"github_recon",...}"  → {phase:github_recon,...}  (keys unquoted)
```

`write_pipeline_exports.py` recorded `phase_load_issues: github_recon.json:malformed`
and set `engine_health.overall=DEGRADED`, while `pipeline_health.md` stayed
`🟢 HEALTHY` because MD is written **before** exports.

## Fix on branch `fix/github-recon-phase-json-md-health-sync`

1. `scripts/sync_pipeline_health_md.py` — rewrite MD Overall from engine_health
2. `scripts/collect_phase_integrity_flags.py` — flag any malformed phase JSON
3. `scripts/apply_github_recon_health_fix.py` — idempotent patcher for the monolith YAML:
   - valid `printf` JSON for github_recon phase
   - empty hits → `EMPTY_VALID`
   - call sync after `validate_pipeline_exports`

**Apply YAML before merge (from repo root):**

```bash
python3 scripts/apply_github_recon_health_fix.py
```

(Or merge this branch after running the applicator and committing the YAML.)

## Contracts unchanged

SI→Hunter OFF · resource caps · Nuclei bulk NOT_RUN · RRP wiring via validate_pipeline_exports

## Offline RRP on artifact #165 (superdrug.com)

Without a new Actions run, RRP scripts were executed on the downloaded #165 results zip:

| Surface | Result |
|---------|--------|
| GATE_0 | **FUNNEL_OK** (live=353, urls=104764, secrets_high=2) |
| SECRETS_REVIEW | **119** review items (not CONFIRMED) |
| EXPOSURE_QUEUE | **118** ranked (top 30 shown) |

This proves operator surfaces work on real artifacts; live post-#58 wiring still needs one light run on current main after YAML apply.

## Offline tests

- sync on #167 fixture → MD Overall becomes DEGRADED
- collect flags on malformed github_recon → warning
- EMPTY_VALID phase → no malformed flag
