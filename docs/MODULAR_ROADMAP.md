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

### ✅ 2026-09-08 — Live probe DIRECT fallback + stage gates (post kyc.com run)
Evidence from run 34172998503 (kyc.com, pre-fix commit):
- Apex returned 301; naabu listed open 80/443; Tor httpx produced 0 live hosts
- Downstream Nuclei/Nikto empty; AI report said "Clean scan" (misleading)

Fixes:
1. After Tor+circuit-retry still empty → DIRECT httpx (no proxychains) on candidates
2. Apex/www seed if curl still sees the target
3. After port scan, if live still empty → DIRECT probe URLs derived from naabu ports
4. Nuclei stage gate: skip when no live hosts (write nuclei/skipped.txt)
5. Security report: never say "Clean scan" when live_hosts=0

### ✅ 2026-09-08 — GitHub recon filter + JS download direct retry
- GitHub code search: quoted domain queries, raw+filtered outputs, noise denylist,
  require domain/base in repo path, cap 80 triage hits (kyc.com noise lesson)
- JS body download: Tor first, then DIRECT retry for failures (403/timeouts);
  better Accept headers; diag file keeps both paths

### ✅ 2026-09-08 — Professional continuous-recon delta
- Diff step writes machine-readable `diff/new_{live,subdomains,urls,js,secrets_high,interesting,nuclei}.txt`
  BEFORE snapshot overwrite (critical ordering fix for accurate deltas)
- Snapshot extended: js_files, secrets_high, interesting, nuclei.jsonl
- `triage/hunter_queue.md` prioritizes Delta section for operators; baseline-aware

### ✅ 2026-09-09 — Full integration pass (post superdrug run 7)

Verified + completed end-to-end:

| Fix | Status |
|-----|--------|
| dns-seed / ports-enriched live recovery | ✅ |
| probe resolved.txt + scheme URLs | ✅ |
| interesting scoring (api-*, non-apex +25) | ✅ |
| scan_order + expensive_targets (top 15–20) | ✅ |
| CDX multi-strategy (text/JSON/www) | ✅ |
| URL root seed if all sources empty | ✅ |
| cariddi via stdin (no invalid -l/-c) | ✅ |
| ffuf -fs 0 + length>0 filter + expensive_targets | ✅ |
| Nuclei/WAF/Info/API/Security/Nikto/Arjun/Corsy/CRLF/Katana caps | ✅ |
| backup content validation + origin block-page filter | ✅ |

Data flow:
resolved → probe → live (seed if needed) → ports enrich → rank → scan_order → expensive_targets
 → crawlers/URLs → JS → targeted → fuzz/nuclei (capped when unverified)
