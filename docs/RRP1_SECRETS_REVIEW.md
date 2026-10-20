# RRP-1 — SECRETS_REVIEW operator surface

## What landed

| Path | Role |
|------|------|
| `scripts/build_secrets_review.py` | Aggregate js / js_deep / SI candidates → REVIEW items |
| `scripts/run_secrets_review.sh` | CLI wrapper |
| `tests/test_build_secrets_review.py` | Offline contracts |

## Operator path (after a run)

1. Download results artifact  
2. Open **`triage/SECRETS_REVIEW.md` first** (once wired)  
3. Then `info_disclosure/`, `js_deep/`, `hunter_queue`  

Status meanings:

| Status | Meaning |
|--------|---------|
| `NO_INPUTS` | Secret steps did not produce files — check funnel (URLs/live) |
| `EMPTY_AFTER_FILTER` | Files existed; all lines looked like placeholders/examples |
| `OK` | One or more REVIEW items (still not CONFIRMED) |

## Workflow wiring (next small PR if not inlined here)

Near the existing **Triage & Prioritization** step in `zero-track-hunter.yml`:

```yaml
- name: RRP-1 Secrets Review (operator surface)
  if: always()
  continue-on-error: true
  timeout-minutes: 2
  run: |
    bash scripts/run_secrets_review.sh "$RESULTS_DIR"
```

Use the same `RESULTS_DIR` / `RD` variable the workflow already exports.

**Do not** feed this output into Hunter as CONFIRMED. SI→Hunter stays OFF.

## Manual offline

```bash
python3 scripts/build_secrets_review.py --results-dir path/to/results/<run>
# → path/to/results/<run>/triage/SECRETS_REVIEW.md
```

## Security

Markdown redacts values. JSON stores redacted lines only. Never paste raw secrets into Discord notifications.
