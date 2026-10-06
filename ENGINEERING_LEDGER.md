# BugBountyCI Engineering Ledger

## HEAD
Latest `main` (nuclei track + LinkFinder export fix). Live verify run in progress on earlier tip.

## Live verification
- **Run:** https://github.com/Tawffik/BugBountyCI/actions/runs/37421731026
- **SHA at dispatch:** `c9c8645` (LinkFinder normalize + Smart Fuzz metrics; health/nuclei_track commits landed after dispatch)
- **Mode:** light · nuva.finance · authorized_open_scan=true
- **Purpose:** prove metrics.json phase semantics + linkfinder_summary on live artifacts

## CLOSED
- Representation Differential (#128)
- Historical pivot → Hunter
- LinkFinder normalize offline + in workflow
- Smart Fuzz false header-count + planned vs post-ac observability (offline)

## Nuclei track
- `scripts/nuclei_track_summary.py` → `meta/nuclei_track.json`
- DEGRADED ≠ CLEAN; separate from core intelligence path
- Wired before `write_pipeline_exports.py`; listed in recon_export.v1

## Export
- JS_TO_ENDPOINT from normalized API/WEB only (not chunk.js flood)
- Artifacts: linkfinder_summary, linkfinder_normalized, smart_fuzzing_metrics, nuclei_track

## Next after harvest of 37421731026
1. Forensic audit metrics + linkfinder_summary + phase smart_fuzzing
2. Mark Smart Fuzz CLOSED if proven
3. Note commits after dispatch need a later run for health row + nuclei_track live proof
