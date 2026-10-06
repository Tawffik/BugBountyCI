# BugBountyCI Engineering Ledger

## HEAD
Latest `main` (LinkFinder normalize + Smart Fuzz observability).

## CLOSED / PROVEN
- **Representation Differential** — #128 / 6c702aa
- **Historical pivot closed loop** — Hunter 40 REDIRECTED

## Smart Fuzzing — IN PROGRESS (offline P0 + observability)
- false interesting_lines from headers — fixed
- planned_requests_ceiling vs post_ac matches — fixed offline (#128: 490 vs 0)
- Live phase-file verify still optional

## LinkFinder normalize — OFFLINE PROVEN
- #128: raw **675** → STATIC **673**, API **0**, UNKNOWN **2**
- `scripts/normalize_linkfinder.py` + summary JSON
- Workflow invokes after raw LinkFinder
- Raw `linkfinder_endpoints.txt` preserved

## Environment
- Sengi quota exhausted → interim `ubuntu-latest`
- Nuclei DEGRADED (~51% errors) — truthful, not clean

## Notion reconciliation
- Fix Control Center was stale (2026-10-03 / 28dd077). Repo ahead.
- Prefer GitHub + artifacts over Notion live queue.

## Next
1. One light live verify (Smart Fuzz metrics + LinkFinder summary) when budget allows
2. Nuclei track separation
3. Restore Sengi when minutes reset
