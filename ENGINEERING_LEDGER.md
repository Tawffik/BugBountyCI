# BugBountyCI Engineering Ledger

## HEAD
Latest `main` after capital.com tip-SHA harvest + export/linkfinder fixes.

## LIVE — tip SHA (#133) capital.com
- **Run:** 37443762040 · SHA `8defe15` · success
- **recon_export.v1:** includes nuclei_track, linkfinder_summary, smart_fuzzing_metrics (**LIVE proven**)
- **nuclei_track:** PARTIAL (timeout, error_rate~44.9) — not CLEAN
- **LinkFinder:** raw 2908 → API 32 · WEB 1216 · STATIC 1519 · EXTERNAL 90
- **Smart Fuzz:** phase empty · state NO_DIFFERENTIAL_SIGNAL · post_ac matches=36 · ceiling 4818
- **Historical:** 40 REDIRECTED → Hunter
- **Hunter:** 44 entries — **4 HIGH_SIGNAL ssrf-v1** (differential; OOB file empty = not confirmed) + 40 historical
- **Representation:** 1 NETWORK_ERROR

## LIVE — #129 nuva.finance (c9c8645)
Smart Fuzz empty honesty + LinkFinder static-only proven earlier.

## Fixes after #133 harvest
- `5d32c7e` JS_TO_ENDPOINT prioritizes API_ROUTE (32/32 vs previous 2/32 under WEB flood)
- linkfinder strip trailing `\\` so `.min.js\\` is STATIC not API

## CLOSED contracts
Representation · Historical→Hunter · Smart Fuzz phase honesty · LinkFinder classify · Export artifact index on tip SHA

## Results path (not fix loop)
1. Human verify capital.com SSRF HIGH_SIGNAL (OOB empty — differential only until confirmed)
2. Consume API routes from linkfinder_normalized (auth/trading endpoints)
3. Richer targets when authorized
4. Sengi when quota returns
