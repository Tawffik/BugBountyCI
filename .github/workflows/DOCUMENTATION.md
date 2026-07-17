# 📖 Ai_tefa.yml — Full Technical Documentation

**Version covered:** 43-step workflow (latest as of this document)
**Purpose:** Reference document for continuing development, onboarding, and planning future upgrades.

---

## 1. Executive Summary

Ai_tefa.yml is a GitHub Actions–based, AI-assisted bug bounty automation pipeline. It performs:

1. **Reconnaissance** — subdomain discovery, live-host probing, port scanning, URL collection, JavaScript analysis, cloud/GitHub/vhost recon
2. **Vulnerability Detection** — Nuclei (3 passes), custom non-destructive injection testing (XSS/SSTI/SQLi/LFI/SSRF/CmdInjection), XXE, GraphQL, IDOR, CORS, sensitive-file exposure
3. **AI Analysis** — up to 6 fallback LLM providers correlate recon output, plan targeted tests, and write a human-readable report
4. **Operational features** — Diff Mode (compare against the last scan of the same target), optional authenticated scanning, screenshots, triage/prioritization, and a polished HTML export

**Scope discipline:** every technique in this pipeline is detection/evidence-only. Nothing in this workflow performs real exploitation, data extraction, or active defeat of security controls (WAF bypass, IP rotation, CAPTCHA solving). This boundary is intentional and documented so future contributors don't accidentally cross it.

---

## 2. Architecture — Phase by Phase

```
┌─ SETUP ──────────────────────────────────────────────────────────┐
│ Checkout → Scope Check → Env Validation → Setup Go/Python        │
│ → Install Deps → Health Check → Cache → Install Tools            │
│ → Verify Tools → Update Nuclei Templates → Create Results Dir    │
│ → Restore Diff-Mode Snapshot                                     │
└────────────────────────────────────────────────────────────────────┘
                              │
┌─ RECONNAISSANCE (produces the raw material everything else uses) ─┐
│ 1. Subdomain Enumeration   (subfinder+assetfinder+crt.sh+brute+   │
│                              alterx permutations, all dnsx-verified)│
│ 2. ASN/CIDR Discovery      (optional, asnmap, needs PDCP_API_KEY)  │
│ 3. Live Host Probing       (httpx: status/title/tech/CDN)          │
│ 4. Port Scanning           (naabu, non-std ports merged into live) │
│ 5. URL Collection          (wayback+gau+katana+robots/sitemap)     │
│ 6. JavaScript Analysis     (downloads JS bodies, greps content)    │
│ 7. Extended Recon          (GitHub code search, vhost discovery,   │
│                              cloud bucket enumeration)             │
│ 8. Content Discovery       (ffuf, fair per-host time budget)       │
│ 9. API Discovery           (Swagger/OpenAPI/GraphQL probing)       │
│ 10. Security Analysis      (CORS misconfig, exposed sensitive files)│
│ 11. Screenshots            (gowitness, first 25 live hosts)        │
└────────────────────────────────────────────────────────────────────┘
                              │
┌─ VULNERABILITY DETECTION ──────────────────────────────────────────┐
│ Nuclei (3 passes: severity-filtered, tech-aware -as, exposure tags)│
│ AI Phase 1: Target Intelligence   → attack_plan.json               │
│ AI Phase 2: Payload Injection     → baseline-compared, evidence     │
│ AI Phase 3: XXE Check             → baseline-compared               │
│ AI Phase 4: GraphQL Attacks       → introspection + batching        │
│ AI Phase 5: IDOR Testing          → baseline-compared, evidence      │
│ AI Phase 6: Chain Analysis        → correlates all findings          │
│ AI Final Report                   → human-readable markdown          │
└────────────────────────────────────────────────────────────────────┘
                              │
┌─ WRAP-UP ───────────────────────────────────────────────────────────┐
│ Diff Against Previous Scan → Save New Snapshot → Triage &            │
│ Prioritization → Professional HTML Export → Count Findings →        │
│ Upload Artifacts (toolchain + results) → Discord Notification       │
└────────────────────────────────────────────────────────────────────┘
```

### Data flow rule
Every phase writes to `results/<timestamp>/<category>/<file>`. Every later phase reads from those exact paths. This was the source of most historical bugs (see §5) — a phase silently not writing its file cascades into every phase that depends on it.

---

## 3. Tool Inventory

| Tool | Pinned Version | Purpose | ⚠️ Update Check (see §6) |
|---|---|---|---|
| subfinder | v2.6.6 | Passive subdomain enum | Check for newer — supports `-recursive` now |
| httpx | v1.6.8 | HTTP probing, tech-detect, response storage | — |
| katana | v1.1.0 | Web crawler | — |
| nuclei | v3.3.2 | Template-based vuln scanning | 🔴 **Outdated — security patch available, see §6.1** |
| dnsx | v1.2.1 | DNS resolution/validation | — |
| assetfinder | v0.1.1 | Subdomain enum (no official newer tag) | — |
| waybackurls | v0.1.0 | Historical URL harvesting (no newer tag) | — |
| gau | v2.2.4 | Historical URL harvesting (multi-source) | — |
| gf | pinned commit (no tagged releases) | URL pattern categorization | — |
| uro | pip package | URL dedup/normalization | — |
| alterx | v0.1.0 | Smart subdomain permutation generation | — |
| naabu | v2.6.1 | Port scanning | — |
| ffuf | v2.1.0 | Content discovery fuzzing | — |
| gowitness | v3.0.5 | Screenshot capture | — |
| asnmap | latest (needs PDCP auth) | ASN → CIDR discovery | — |

**Why pinned, not `@latest`:** an upstream rename/removal (like the original `ameenmaali/uro` disappearing) can silently break the whole pipeline. Pinning means updates are a deliberate, tested decision, not something that happens to you mid-scan.

---

## 4. Configuration Reference

### Inputs (workflow_dispatch / workflow_call)
- `target` (required) — domain to scan
- `hunting_mode` — `light` / `normal` / `aggressive` (controls test-count caps)
- `discord_notify` — boolean

### Secrets (all optional except none are required — the pipeline degrades gracefully)
| Secret | Purpose | Free tier? |
|---|---|---|
| `ANTHROPIC_API_KEY` | AI provider 1 | No |
| `OPENROUTER_API_KEY` | AI provider 2 (paid model) + provider 3 (free model fallback) | Free model available |
| `GROQ_API_KEY` | AI provider 4 | **Yes** |
| `GEMINI_API_KEY` | AI provider 5 | **Yes** |
| `OPENAI_API_KEY` | AI provider 6 | No |
| `PDCP_API_KEY` | Enables ASN/CIDR discovery (asnmap) | Free signup |
| `GITHUB_TOKEN` | Enables GitHub code-search recon | Auto-provided by Actions |
| `AUTH_COOKIE` | Authenticated scanning (session cookie) | — |
| `AUTH_HEADER` | Authenticated scanning (e.g. Bearer token) | — |
| `DISCORD_WEBHOOK` | Completion notification | — |

### Key environment variables (set once, used everywhere)
- `SCAN_USER_AGENT` — realistic browser UA used by every tool that sends HTTP requests
- `ANTHROPIC_MODEL_NAME`, `OPENROUTER_MODEL_NAME`, `OPENROUTER_FREE_MODEL_NAME`, `GROQ_MODEL_NAME`, `GEMINI_MODEL_NAME`, `OPENAI_MODEL_NAME` — change a model in one place, not six

---

## 5. Design Decisions & Bug Catalog (lessons already learned)

This section exists so the same mistakes aren't repeated.

| # | Bug | Root Cause | Fix Pattern |
|---|---|---|---|
| 1 | `uro@latest` install failed | Wrong repo (Go fork of a Python tool) | Install via `pip`, not `go install` |
| 2 | Tool install failure blocked PATH export | `GITHUB_PATH` export was the *last* line in the step | Move PATH export to the *first* line |
| 3 | Discord notification never fired | `inputs.discord_notify == 'true'` compares bool to string (always false in GH Actions expression math) | Compare to bare `true` |
| 4 | IDOR always tested the same broken URL | ID substring was stripped from the template before substitution | Keep full URL + exact matched substring |
| 5 | `httpx -paths` / `dnsx -H` / `ffuf -silent` / `gau -subs` | Wrong flag name/form for that specific tool's CLI parser (pflag vs plain flag package have different single/double-dash rules) | **Verify every flag against the tool's own `--help`/docs, per tool** — never assume convention carries across tools |
| 6 | `grep -c PATTERN \|\| echo 0` produced `"0\n0"` | `grep -c` still prints "0" AND exits 1 on zero matches, so the `\|\|` fallback ALSO fires | Use `\|\| true` + `${VAR:-0}` default instead |
| 7 | Case-sensitive subdomain filter | `grep -E` is case-sensitive by default; DNS names from tools are lowercase but user-typed target might have uppercase | Normalize target to lowercase once, globally, right after input validation |
| 8 | DNS brute-force / `uro` hung and starved the rest of the step | No per-command timeout; a slow/hanging external tool blocks everything after it in the same step, even past the fallback `\|\|` | Wrap every external tool call that processes bulk/unbounded input with `timeout N` |
| 9 | Content Discovery Fuzzing never finished for later hosts | Sequential loop with no per-host time cap — one slow host ate the whole step's budget | Divide the step's time budget evenly across hosts, `timeout` each host's share |
| 10 | JS Analysis found nothing, ever | Searched the *list of JS file URLs* for keywords instead of the *downloaded file contents* | `httpx -sr -srd` to store response bodies, then grep those |
| 11 | False positives across XXE/LFI/SQLi/Sensitive-Files | Naive keyword matching with no comparison to a "normal" response | Baseline-diff pattern: fetch a control response first, only flag if the signal is present in the test response AND absent from baseline |
| 12 | AI's target priority/custom payloads were ignored | Downstream code re-derived its own generic payloads instead of using the AI's `priority`/`payloads` fields | Sort by AI priority before capping; test AI payloads first, generic ones as backup |
| 13 | Job-level timeout smaller than sum of step timeouts | Each step's timeout was set individually without checking the total against the job-level cap | Always recompute `sum(step timeouts)` vs job `timeout-minutes` after adding/changing any step |

**General principle that produced most of these fixes:** *simulate the failure mode, don't just read the code.* Several of these bugs produced **zero errors** and looked like "clean scans" — the only way to catch them was tracing file timestamps and testing the exact command with real data.

---

## 6. Update Backlog (researched from current tool releases & community practice)

### 6.1 🔴 High priority — Nuclei security patch
Nuclei releases after our pinned v3.3.2 include fixes for two documented vulnerabilities in nuclei itself (JS-protocol templates able to read files outside the intended sandbox; template expressions evaluable from non-template sources). **Action:** re-pin nuclei to the current stable release and re-verify the `-mhe`/`-as`/`-tags` flags still behave identically (flag behavior has changed between minor versions before in this project's history — see bug #5).

### 6.2 Recursive subdomain enumeration
Community pipelines commonly add `-recursive` to subfinder (re-feeds first-level results back in for deeper discovery) instead of relying only on permutation (alterx). Worth evaluating as a complementary source.

### 6.3 Port scan + service fingerprinting combo
Some current community recon docs chain `naabu -nmap-cli 'nmap -sV -sC'` to get service/version banners on discovered ports, beyond what httpx alone reports for HTTP(S). Would need nmap installed and a time-budget review (service scans are slower than a pure port sweep).

### 6.4 Certificate-transparency alternative source
Some pipelines add a second CT-log source (beyond crt.sh) since crt.sh has occasional outages/rate limits. Worth a fallback source if crt.sh returns empty.

### 6.5 GitHub recon signal-to-noise
Confirmed in a real run: generic queries like `"target.com password"` mostly return unrelated repos (domain block-lists, bloatware lists) that happen to mention the domain. Consider narrowing queries (e.g. restrict to filenames like `.env`, `config.*`, or combine with `org:` if the company's GitHub org is known) to raise signal quality.

### 6.6 Admin-path testing against raw IPs
Non-standard-port hosts discovered via naabu are tested for admin paths without an explicit `Host:` header — against a shared Cloudflare edge IP this likely doesn't reach the actual backend. Needs either skipping raw-IP admin-path testing or explicitly setting `-H "Host: <original-domain>"`.

### 6.7 LLM-based finding correlation (already partially implemented)
Current community frameworks are converging on "LLM intelligence" layers similar to our AI Agent phases — validates that this workflow's architecture is aligned with where the field is heading, not behind it.

---

## 7. Known Limitations (by design, not bugs)

- **No exploitation/data-extraction capability** — confirmed detection only produces evidence (baseline vs test diff), never dumps real data.
- **No WAF-bypass/evasion tooling** — realistic User-Agent and respectful rate limits are the ceiling; IP rotation, TLS fingerprint spoofing, and similar techniques are explicitly out of scope.
- **GitHub Actions hard cap: 360 minutes/job** — the job timeout (358 min) is tuned right under this; any new step must recheck the total budget (§5, bug #13).
- **Diff Mode cache is single-slot per target** — only the immediately previous scan is kept, not a full history.

---

## 8. How to Extend This Workflow

1. **Before adding a tool:** verify its exact flag names against its own `--help` output or current official docs — do not assume conventions from other tools in this same pipeline apply.
2. **Before adding a step:** recompute the time budget (§5 bug #13) and decide whether it needs continue-on-error + a bounded internal timeout.
3. **Before trusting a "finding":** ask whether it's baseline-compared. If not, it's probably prone to false positives (§5 bug #11 pattern).
4. **Test with mock data first** — several of the worst bugs in this project's history looked syntactically correct and only failed with real-world data/timing.
