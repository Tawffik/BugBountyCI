# Competitive analysis — modern bug bounty automation (2025–2026)

Research snapshot used to guide Zero Track development. Goal: adopt **ideas that fit GitHub Actions-hosted CI**, not copy unrelated platforms.

## Categories reviewed

| Category | Examples | Fit for Zero Track? |
|----------|----------|---------------------|
| Full recon frameworks (local/VPS) | reconFTW, bbot, recon0, CrounsEngine / BountyRecon | Ideas yes; full embed no (too heavy for GHA minutes) |
| Distributed recon | Axiom + PD stack | Out of scope without cloud fleet |
| AI agent platforms | BugTraceAI, HexStrike, Shannon-class tools | Optional AI *assist* only; not autonomous exploit loops on shared runners |
| Continuous recon playbooks | bugbounty.info pipeline, notify + delta | **High fit** |
| Scope / program intel | ProjectDiscovery Chaos lists, scope crawlers | Optional later |
| Browser workbenches | In-browser BB frameworks | Different product |
| Company BB platforms | Gerobug | Not a hunter pipeline |

## What strong projects do well

### 1. Stage gates (recon0)
If DNS/live is empty, stop early instead of running 40 empty scanners.
**We already** use fallbacks and `continue-on-error`; further gate tightening is on the roadmap.

### 2. Continuous / delta recon (industry playbooks)
The money is often **what changed**: new subdomain, new port, new JS, new panel.
**We have** snapshot diff mode; **we now emit** `triage/hunter_queue.md` including **new live hosts** vs previous snapshot.

### 3. Headless browser crawl (recon0 / chromedp)
Runtime JS + HAR beats static script-src lists.
**Fit:** valuable but expensive on GHA + Tor. Keep gowitness screenshots; defer full CDP crawl unless self-hosted runners.

### 4. Strict scope enforcement (CrounsEngine-style)
Filter every host/URL against in-scope rules.
**We have** authorized-scope verification at start; deepen URL-level scope filters later if multi-domain programs expand.

### 5. Event-driven graphs (bbot)
Powerful asset graph; wrong runtime for a single GHA job.
**Takeaway:** keep structured folders + ranked lists, not a full graph DB on the runner.

### 6. AI for triage, not volume
2025–2026 market problem: AI-generated low-signal reports.
**Our stance:** AI phases optional; **hunter_queue + secrets_high + severity sort** push humans toward evidence-backed work.

### 7. Tooling stack consensus
Nearly every serious pipeline still centers **ProjectDiscovery** (subfinder, dnsx, httpx, naabu, nuclei, katana) + JS miners + ffuf.
Zero Track is aligned with that consensus, with extra reliability engineering for Tor/GHA.

## What we deliberately will not add

- Autonomous “exploit until shell” agent loops on GitHub-hosted runners  
- Mass destructive scanning / credential stuffing executed unattended  
- Dependency on paid SaaS scanners as hard requirements  
- C2 / post-exploitation frameworks  

## Positioning of Zero Track

```text
                    Local power tools          Zero Track (this repo)
                    (bbot, reconFTW, recon0)    GitHub Actions CI hunter
Runtime             Your VPS / laptop          Ephemeral GHA runner + Tor
Strength            Depth, browser crawl       Repeatable CI, artifacts, diff
Weakness            Ops burden                 Minutes / rate limits
Best use            Daily deep recon           Scheduled or on-demand authorized scans
```

**Differentiation we invest in:**

1. Interesting-host ranking → unified `scan_order.txt`  
2. Tor-aware reliability (safe merges, concurrency caps)  
3. High/low secret classification  
4. Operator **hunter queue** (what to do next)  
5. Portfolio-grade docs and ethical defaults  

## Next research-backed upgrades (priority order)

1. Stronger **stage gates** when live hosts = 0  
2. Optional **waymore** / extra passive URL sources when CDX throttles  
3. URL-level **scope allowlist** for wildcard programs  
4. Richer **delta** (new JS files, new nuclei templates hits) in hunter_queue  
5. Composite actions modularization for maintainability  

---

*Last updated: 2026-09-08. Sources: public GitHub projects and recon methodology write-ups (recon0, bbot, reconFTW, CrounsEngine, bugbounty.info playbook, ProjectDiscovery ecosystem, 2026 methodology repos).*
