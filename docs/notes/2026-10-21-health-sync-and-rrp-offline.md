# 2026-10-21 — Health JSON/MD sync + RRP offline proof

## Defect (run #167)

`meta/phases/github_recon.json` was invalid JSON due to shell quoting:

```text
echo "{"phase":"github_recon",...}"  → {phase:github_recon,...}
```

`write_pipeline_exports` set `engine_health.overall=DEGRADED` while `pipeline_health.md` stayed HEALTHY.

## Fix (this branch)

1. `scripts/sync_pipeline_health_md.py`
2. `collect_phase_integrity_flags.py` flags any malformed phase JSON
3. `apply_github_recon_health_fix.py` — run once from repo root to patch the monolith YAML

```bash
python3 scripts/apply_github_recon_health_fix.py
git add .github/workflows/zero-track-hunter.yml
git commit -m "fix(workflow): valid github_recon phase JSON + health MD sync"
```

## Contracts unchanged

SI→Hunter OFF · caps · Nuclei bulk NOT_RUN

## Offline RRP on artifact #165

| Surface | Result |
|---------|--------|
| GATE_0 | FUNNEL_OK |
| SECRETS_REVIEW | 119 review items |
| EXPOSURE_QUEUE | 118 ranked |
