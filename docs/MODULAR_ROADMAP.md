# Modular Architecture Roadmap — BugBountyCI

## Why this change?
The previous `zero-track-hunter.yml` was a single ~300 KB / 4500-line job with 63 sequential steps.
This made it:
- Almost impossible to edit safely from mobile
- Hard to test individual phases
- High risk of YAML / logic breakage on every change

## Target Structure

```
.github/
├── workflows/
│   └── zero-track-hunter.yml          # Thin orchestrator only
├── actions/
│   ├── setup-toolchain/action.yml     # Go + Python + tool install
│   ├── setup-tor/action.yml           # Tor + proxychains + bootstrap
│   ├── subdomain-enum/action.yml
│   ├── live-probe/action.yml          # ← first extracted (2026-09-08)
│   ├── url-collection/action.yml
│   ├── js-analysis/action.yml
│   ├── targeted-scanners/action.yml
│   ├── nuclei-scan/action.yml
│   └── ai-agent/action.yml
```

## Progress

### ✅ 2026-09-08 — Critical reliability fix (Live Host Probing)
- Root cause of empty `live.json` / `live.txt` identified:
  Parallel background jobs appending JSON to the same file → corrupted NDJSON.
- Fixed by writing each probe result to its own temp file, then safe merge.
- Concurrency lowered from 12 → 4 (Tor cannot sustain high parallel circuit builds).
- `jq` extraction made NDJSON-safe + sorted unique.

### Next planned extractions
1. `setup-tor` composite action
2. `live-probe` composite action (full step)
3. Split the main workflow into phase jobs with artifact passing where safe

## Design principles going forward
- One logical phase = one composite action or reusable workflow
- Results always written under `results/${TIMESTAMP}/...`
- Tor state is shared (setup once, used by later steps)
- Prefer reliability and signal quality over raw quantity of tools
