# Zero Track — AI-Assisted Bug Bounty CI

[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Automated-2088FF?logo=githubactions&logoColor=white)](https://github.com/Tawffik/BugBountyCI/actions)
[![Workflow](https://img.shields.io/badge/Pipeline-60%2B%20steps-success)](./.github/workflows/zero-track-hunter.yml)
[![Scope](https://img.shields.io/badge/Scope-Authorized%20targets%20only-orange)](#legal--ethics)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

> **Autonomous reconnaissance & vulnerability discovery pipeline** that runs on GitHub Actions.
> Built for serious bug bounty workflows: prioritize high-value assets, reduce noise, and produce actionable reports — not just tool dumps.

---

## Why this project exists

Most automated recon pipelines:

- Scan the **apex domain** and miss admin / API / staging hosts
- Dump **thousands of false-positive “secrets”** from minified JS
- Break under **Tor / proxy** concurrency and produce empty results
- Are a **single unmaintainable YAML** that nobody can extend safely

**Zero Track** is engineered against those failure modes:

| Problem | Approach in this repo |
|--------|------------------------|
| Apex-only scanning | Host scoring (`admin`, `api`, `staging`, `dev`, non-standard ports) → unified `scan_order.txt` |
| Noisy JS secrets | Split into **high-confidence** key formats vs filtered low-confidence |
| Flaky live probing over Tor | Safe per-host result merge + bounded concurrency |
| Empty passive URL sources | CDX limited fallback + urlscan.io + multi-source merge |
| Scanner budget wasted | Nuclei, ffuf, Arjun, Nikto, crawlers all consume **interesting-first** order |

---

## Pipeline overview

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  SETUP                                                                   │
│  Scope check → Tor proxy → Toolchain (Go/Python) → Nuclei templates      │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  RECON                                                                   │
│  Subdomains → ASN/CIDR → Takeover check → Live probe → Ports             │
│  → Interesting-host ranking → scan_order (single source of truth)        │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  DISCOVERY                                                               │
│  URLs (wayback/gau/katana/hakrawler/urlscan) → JS analysis → Deep JS     │
│  → Content discovery → API / GraphQL / Swagger → Cloud origin            │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  DETECTION                                                               │
│  Nuclei (critical/high + exposure tags) → Targeted (Dalfox, Arjun,       │
│  Corsy, CRLFuzz, Subzy) → Info disclosure → Optional AI agent phases     │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  OUTPUT                                                                  │
│  Triage → Diff vs previous scan → HTML/Markdown report → Artifacts       │
│  → Optional Discord notify → Nuclei SARIF → Security tab                 │
└─────────────────────────────────────────────────────────────────────────┘
```

**60+ orchestrated steps** in one workflow, with reliability fixes validated against real runs.

---

## Features

### Reconnaissance
- Passive + active subdomain enumeration (Subfinder, Amass, Assetfinder, DNS brute, permutations)
- ASN / CIDR expansion and live host probing (httpx over Tor with safe concurrency)
- Port discovery (naabu) including high-value ports (8080, 8443, 9200, 27017, …)
- **Interesting-host scoring** and unified scan order for all downstream tools
- URL collection with resilient fallbacks when archive.org rate-limits runners
- JavaScript body download, deep extraction (LinkFinder, SecretFinder, TruffleHog, Gitleaks, Cariddi)
- Cloud origin discovery and optional WAF-related header checks

### Vulnerability signal
- Nuclei multi-pass (severity/high, tech-aware, exposure/panel/config tags)
- Parameter discovery (Arjun), XSS (Dalfox), CORS (Corsy), CRLF, takeover (Subzy)
- Information disclosure paths (`.git`, backups, common config files)
- Optional authenticated scanning via cookie / header secrets
- Optional multi-provider AI phases for prioritization and report narrative

### Operations
- Diff mode against the previous scan of the same target
- Screenshot capture (gowitness via Chrome SOCKS proxy)
- Structured artifacts per run + triage helpers
- Discord notification hook
- Designed to run on **GitHub-hosted runners** with no self-hosted infra required

---

## Quick start

### 1. Fork or clone

```bash
git clone https://github.com/Tawffik/BugBountyCI.git
cd BugBountyCI
```

### 2. Configure secrets (optional but recommended)

Repo → **Settings → Secrets and variables → Actions**

| Secret | Purpose |
|--------|---------|
| `DISCORD_WEBHOOK` | Run summary notifications |
| `ANTHROPIC_API_KEY` / `OPENROUTER_API_KEY` / `GROQ_API_KEY` / `GEMINI_API_KEY` / … | AI agent phases (any one can work as fallback) |
| `AUTH_COOKIE` / `AUTH_HEADER` | Authenticated surface scanning |
| `TOR_BRIDGE_LINES` | Tor bridges if the runner network blocks direct Tor |
| `PDCP_API_KEY` | ProjectDiscovery Cloud (ASN helpers) |

### 3. Run a scan

1. Open **Actions** → **Zero Track - AI Autonomous Hunter**
2. Click **Run workflow**
3. Set:
   - **target** — domain you are authorized to test (e.g. `example.com`)
   - **hunting_mode** — `light` / `normal` / `aggressive`
   - toggles for WAF recon, git exposure, source maps as needed
4. Wait for completion → download the **results artifact**

### 4. Read the output

Typical artifact layout:

```text
results/<run-id>-<target>/
├── live/           # live hosts, ports, interesting ranking, scan_order
├── urls/           # merged URLs, gf categories
├── js/             # bodies, api_endpoints, secrets_high / secrets_low
├── targeted/       # arjun, dalfox, corsy, …
├── nuclei/         # findings.jsonl, exposure pass
├── fuzzing/        # content discovery hits
├── ai/             # security report (if AI configured)
├── report/         # exported report
└── logs/           # per-tool logs for debugging
```

Start with:

1. **`triage/hunter_queue.md`** — operator queue (priority hosts, high secrets, top findings, delta hosts)
2. `live/interesting_ranked.txt` — where the pipeline focused
3. `js/secrets_high.txt` — high-confidence credentials/patterns
4. `nuclei/findings.jsonl` — confirmed template hits
5. `targeted/` and `fuzzing/discovered.txt` — manual follow-up leads

---

## Hunting modes

| Mode | Intent | Typical trade-off |
|------|--------|-------------------|
| `light` | Fast signal | Shorter budgets, fewer hosts/URLs |
| `normal` | Balanced (default) | Production default for most programs |
| `aggressive` | Maximum coverage | Longer runtime, deeper fuzz/JS caps |

---

## Architecture notes (for reviewers)

- **Single orchestration workflow:** `.github/workflows/zero-track-hunter.yml`
- **Reliability engineering:** parallel JSON/text corruption fixed via per-task temp files; Tor-friendly concurrency caps
- **Data flow:** `live.txt` → score → `interesting.txt` → `scan_order.txt` → all scanners
- **Quality over volume:** secrets and findings are structured for triage, not raw greps only
- **Roadmap:** modular composite actions (see `docs/MODULAR_ROADMAP.md`) so the monolith can be split without losing behavior

How we compare to other frameworks: [`docs/COMPETITIVE_ANALYSIS.md`](./docs/COMPETITIVE_ANALYSIS.md)  
Technical deep-dive: [`docs/DOCUMENTATION.md`](./docs/DOCUMENTATION.md)  
Phase manifest: [`docs/PIPELINE_MANIFEST.md`](./docs/PIPELINE_MANIFEST.md)  
Methodology notes: [`docs/methodology.md`](./docs/methodology.md)

---

## Project structure

```text
BugBountyCI/
├── .github/
│   ├── workflows/
│   │   ├── zero-track-hunter.yml   # Main autonomous hunter
│   │   └── 01.yml                  # Optional subdomain monitor (manual)
│   └── wordlists/
├── docs/
│   ├── DOCUMENTATION.md            # Full technical reference
│   ├── PIPELINE_MANIFEST.md        # Step-level manifest
│   ├── MODULAR_ROADMAP.md          # Evolution / modularization plan
│   ├── methodology.md
│   └── dorking_engine.py           # Supporting recon utilities
├── results/                        # Optional local samples (not required to run)
├── LICENSE
└── README.md
```

---

## Legal & ethics

This project is intended **only** for:

- Targets you own
- Targets covered by an explicit bug bounty / VDP authorization
- Lab and educational environments

Unauthorized scanning may be illegal. You are solely responsible for compliance with applicable laws and program rules. The pipeline is designed for **detection and evidence collection**, not destructive exploitation.

---

## Skills demonstrated

Built and iterated as a production-style security automation system:

- End-to-end **CI/CD for offensive security** on GitHub Actions
- **Failure-mode analysis** from real runs (empty artifacts, SIGPIPE, Tor circuit limits)
- **Signal ranking** and budget-aware scanning
- Multi-tool orchestration (Go, Python, Nuclei ecosystem)
- Operational reporting, diffing, and triage workflow design

---

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for how to propose changes safely (this workflow is large; small, tested diffs are preferred).

---

## Author

**Tawffik** — [GitHub](https://github.com/Tawffik)

If this repo is useful for your workflow or hiring evaluation, a star is appreciated.

---

## Disclaimer

Provided as-is, without warranty. Use responsibly and only on authorized targets.
