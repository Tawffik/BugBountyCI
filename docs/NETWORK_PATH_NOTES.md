# Network path notes (GitHub Actions runners)

## What actually blocks us

1. **TLS / JA3 fingerprint** (Go tools: httpx, ffuf, nuclei) — Cloudflare/Akamai
   often reject non-browser ClientHello *before* HTTP. Changing User-Agent alone
   does not fix this.
2. **Shared runner IP reputation** — many programs share the same Azure ranges.
3. **Tor** — rotates exit IP but exits are flaky, slow, and often blocked as
   "anonymous relay"; still not a browser TLS fingerprint.

## What we implemented

| Control | Purpose |
|---------|---------|
| `httpx -tlsi` | Experimental JA3 randomization (httpx ≥1.6) |
| `curl` fallback + `scripts/curl_tech_detect.py` | Status + tech when httpx fails (curl OpenSSL ≠ Go TLS) |
| Browser-like headers | Close cheap header-only bot signals |
| ffuf `-s` restored + `[ffuf-diag]` | Silent + one-line Errors/exit observability |
| DIRECT-first for asnmap / nuclei | Avoid Tor for non-target APIs and heavy scanners |

## What does *not* work well on hosted runners

- **Fake "Tor-like" UA/IP rotation without a real proxy** — still one GitHub IP + Go TLS.
- **Free open proxies** — unsafe, unstable, often worse than Tor.
- **Whitelisting the runner on the *target's* Cloudflare** — only works if *you*
  own that zone (irrelevant for bug bounty against third parties).

## Better options (operator choice)

1. **Optional HTTPS proxy secret** (residential or static)  
   Set `HTTPS_PROXY` / `HTTP_PROXY` (and optionally `ALL_PROXY`) as repo secrets
   and export them in the workflow for probe/fuzz steps. Real IP diversity.
2. **Self-hosted runner** on a VPS with a clean residential/datacenter IP.
3. **Stay with current stack** — accept that some CF sites will only get curl
   status/tech, and prioritize JS/API intelligence (Priority 1) over perfect live tech.

Do not build a custom "mini-Tor" inside the workflow; it will not beat JA3 and
adds maintenance cost without evidence of gain.

## Job network policy (2026-09-24)

| Variable | Meaning |
|----------|---------|
| `NETWORK_MODE=direct_then_tor` | DIRECT (runner IP) first; Tor only as per-host fallback when `USE_TOR=true` |
| `USE_TOR=true` | Allow Tor fallback on live probe if DIRECT empty for that host |
| GitHub-hosted IPs | Often blocked by targets → fallback Tor still available on live |
| sengi / self-hosted | Prefer DIRECT; Tor is optional and must not be primary |

Quality gates write `meta/phases/*.json`. If `SKIP_HEAVY_SCAN=true` (live < 3),
Nuclei/Nikto soft-skip — empty findings are **not** a clean-target verdict.
