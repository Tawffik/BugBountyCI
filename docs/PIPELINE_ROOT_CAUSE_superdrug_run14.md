# Root cause analysis — superdrug.com run #14

## What looked broken
- Collected URLs: **0** (previous run had ~740)
- ASN/CIDR candidates: **0** (previous had ~2020)
- Many scanners "no results"
- Nuclei timeout / high error rate
- Tor/asnmap empty logs

## Evidence from artifacts
| File | Size / lines | Note |
|------|----------------|------|
| urls/wayback.txt | **5000 lines** | Valid http URLs present |
| urls/wayback_js.txt | ~283KB | Present |
| urls/all.txt | **0 bytes** | Wiped after merge |
| urls/gau.txt | 0 | gau timed out (non-fatal) |
| logs/asnmap.log | 0 | asnmap via Tor returned nothing |
| live/live.txt | 24 hosts | Live probing actually worked |
| live/ports.txt | 16 lines | Port data existed |

## Root cause #1 — uro emptied urls/all.txt (CRITICAL)
Merge step was:
```bash
timeout 90 uro < /tmp/urls_merged.txt > "$RD/urls/all.txt" || cp /tmp/urls_merged.txt "$RD/urls/all.txt"
```
uro often exits **0** with **empty stdout** on noisy CDX/wayback input.
The `|| cp` fallback only runs on **non-zero** exit, so a successful empty uro permanently zeroed the corpus.

Downstream (JS mining, gf, juicy, nuclei URL templates, AI agents) all starved → tools produce nothing.

## Root cause #2 — asnmap only via Tor
asnmap talks to ProjectDiscovery Cloud / public ASN data, **not** the target WAF.
Tor exits were flaky → empty output, empty log, 0 CIDRs.

## Root cause #3 — Not primarily Tor for everything
Live hosts (24) were found. Passive collection sources (wayback) worked.
The failure is **post-processing (uro)** and **asnmap path**, not total network death.

## Fixes applied (in restored workflow payload)
1. Merge excludes all.txt/juicy/gf from cat inputs
2. Keep pre-uro merge if uro empty or fails
3. Final safety copy if all.txt still empty
4. asnmap: **DIRECT first**, then Tor retries
5. Log uro outcomes to logs/uro.log

## What you should do
1. Run workflow_dispatch once on this bootstrap to restore full YAML
2. Re-run full hunt on superdrug.com
3. Confirm urls/all.txt is non-zero in artifacts
