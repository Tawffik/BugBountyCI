# BugBountyCI — PROJECT STATE

## MODE
CONTINUE — P0 workflow integrity restored; always-record live verification in progress

## MAIN HEAD
`829140882be63e62810c9c0d98a8474882974b49`
- zero-track-hunter.yml **351118 bytes** (restored from placeholder corruption)
- always-record: `record_probe()` after every non-000 fixed-path curl, PROBE_CAP=48
- payload self-heal: `.github/workflows/_payload/part_*.b64` + `self-heal-zero-track.yml`

## CRITICAL RECOVERY
- Root: Contents-API truncation → 40-byte placeholder on main @ 81c6966
- Fix: PR #16 squash-merged (`fix/restore-wf-payload-assemble` → main)
- Offline tests: 56 OK (record, body classifier, github_recon benchmarks, SI, historical, etc.)

## LIVE VERIFICATION
- Run **#152** / `38611194554` capital.com light on tip `8291408` — **in_progress**
- Purpose: prove probe_results.jsonl receives bounded non-000 bodies (SPA/AUTH/WAF samples)
- Do not claim always-record live until harvest

## PRIOR BATCH (historical evidence only)
#147–#151 on ea7fa9a8 — phase success, probe_results EMPTY under positive-only emitter

## BOUNDARIES HELD
- dorking_engine: IMPLEMENTED_NOT_INVOKED
- SI→Hunter: OFF
- No new scanners without measured value

## NEXT
1. Harvest #152 probe_results.jsonl schema/counts/redaction/classifier dispositions
2. Ledger + Notion FCC reconcile after harvest
3. Independent READY tasks only after P0 live proof or explicit blocker
