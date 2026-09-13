# ASN / CIDR discovery hardening (2026-09-13)

## Goal
Stop silent `ASN = 0` with empty logs; persist CIDR ranges; port-scan ranges without Tor when possible.

## Pipeline now

1. **asnmap DIRECT** by domain (`-d`)
2. If empty → **asnmap by IP** seeds from apex/www/onlinedoctor/api + up to 30 `resolved.txt` hosts
3. If still empty → Tor asnmap retries (existing)
4. On CIDR success → save **`subdomains/asn_cidrs.txt`** + **naabu DIRECT** (Tor only if DIRECT empty)
5. If asnmap exhausted → **BGPView** (multi-IP) free API + save CIDRs + naabu DIRECT
6. If no `PDCP_API_KEY` → same free BGPView path (existing) with DIRECT naabu

## Artifacts

| File | Meaning |
|------|---------|
| `subdomains/asn_cidrs.txt` | CIDR prefixes discovered |
| `subdomains/asn_ips.txt` | `https://ip:port` candidates from naabu |
| `meta/asn_source.txt` | asnmap / bgpview / ... |
| `meta/asn_skipped_reason.txt` | Why discovery degraded |
| `logs/asnmap.log` / `logs/bgpview.log` | Diagnostics |

## Operator tip
Set `PDCP_API_KEY` for best asnmap coverage. Free APIs are a fallback, not a full org inventory.
