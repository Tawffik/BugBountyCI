---
## 2026-10-21 — fix: health MD/JSON honesty + github_recon phase JSON root (#167)

- **Root cause:** shell `echo "{"phase":...}"` wrote invalid phase JSON → `phase_load_issues` → `engine_health.overall=DEGRADED` while `pipeline_health.md` stayed HEALTHY (MD written before exports).
- **PR #60 merged:** scripts on main
  - `scripts/sync_pipeline_health_md.py`
  - `collect_phase_integrity_flags.py` (any malformed phase)
  - `scripts/apply_github_recon_health_fix.py` (idempotent YAML patcher; shell JSON verified offline)
- **YAML apply still required once on main:**
  ```bash
  python3 scripts/apply_github_recon_health_fix.py
  git add .github/workflows/zero-track-hunter.yml
  git commit -m "fix(workflow): valid github_recon phase JSON + health MD sync"
  git push
  ```
- **Contracts unchanged:** SI→Hunter OFF · caps · Nuclei bulk NOT_RUN · RRP wiring intact.
- **Offline:** sync on #167 fixture → MD DEGRADED; applicator verified (OK + EMPTY_VALID parse as JSON); RRP offline on #165 (GATE_0 FUNNEL_OK, SECRETS 119, EXPOSURE 118).
- **Closed PR #59:** do not merge (workflow damaged on that branch only; main never touched).
---

