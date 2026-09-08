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

### ✅ 2026-09-08 — URL Collection reliability
- Limited CDX fallback when full waybackurls returns empty (common under runner IP rate-limits).
- Secondary gau retry without `--subs`.
- Added urlscan.io passive source (no key required).
- Goal: keep downstream JS / vuln phases fed with real URLs even when primary passive sources fail.

### ✅ 2026-09-08 — JavaScript Analysis quality
- Secrets split into high-confidence (real key formats) vs low-confidence (filtered generic).
- Removed massive false-positive sources (minified framework noise, webpack markers).
- fetch/axios calls moved to api_endpoints (not treated as secrets).
- JS download concurrency 10 → 4 for Tor stability.
- Result: triage-usable secrets instead of 800KB+ noise.

### ✅ 2026-09-08 — Attack surface prioritization (subdomains + ports → exploit)
- Fixed port-scan parallel-write corruption; expanded high-value ports.
- Ranked live hosts by interestingness (admin/api/staging/dev/internal/CI/DB + nonstd ports).
- ffuf / Arjun / Nuclei now hit interesting hosts FIRST, then the rest.
- Goal: stop wasting scan budget on apex-only; push exploitation toward where bugs actually live.

### ✅ 2026-09-08 — Unified scan_order integration
- Created `live/scan_order.txt` as single source of truth (interesting hosts first, then rest).
- Wired ALL major downstream scanners to it:
  katana, hakrawler, robots/sitemap, cariddi, arjun, corsy, crlfuzz,
  info-disclosure, AI-infra, ffuf, API discovery, security analysis,
  screenshots, nuclei, nikto.
- Removed duplicated prioritization logic from individual steps.
- Result: attack-surface ranking actually drives exploitation coverage end-to-end.
