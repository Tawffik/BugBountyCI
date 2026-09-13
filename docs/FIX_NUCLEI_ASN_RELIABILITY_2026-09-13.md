# Fix: Nuclei + ASN reliability (2026-09-13)

Based on superdrug run **#65** and earlier root-cause notes.

## Symptoms (run 65)

| Stage | Symptom |
|-------|---------|
| Nuclei | `matched: 0`, ~27k errors, **~50% error rate** |
| ASN | 0 CIDRs after 3 attempts (Tor-flaky signature) |
| GAU | empty file (timeout / provider) |
| findings.jsonl | empty (downstream of Nuclei) |

## Root causes

1. **Nuclei over Tor** cannot sustain template volume → mass failures, not “clean target”.
2. **Soft critical_seeds** in `live.txt` made Nuclei probe hosts that never responded.
3. **asnmap -d** alone sometimes returns empty even with PDCP key; IP lookup helps.
4. GAU single-shot timeout was tight on large domains.

## Changes

### Nuclei (`☢️ Nuclei Vulnerability Scan`)

- Prefer `verified.txt` over soft `live.txt` / seeds.
- Hard-cap targets (12 verified / 8 unverified path).
- Optional filter against `ports.txt` / interesting / verified.
- **Pass 1–3 on DIRECT** (no proxychains): critical+high, `-as`, exposure tags.
- **Tor only if DIRECT findings == 0** (low rate last resort).
- Write `meta/nuclei_path.txt` + `meta/nuclei_summary.txt`.

### ASN

- Keep DIRECT-first by domain.
- New: resolve apex/www → **asnmap -i** IP list.
- Then Tor retries as before.

### GAU

- Timeout 240s.
- Explicit `--providers wayback,commoncrawl,otx,urlscan`.

## Still operator-side (cannot fully code-fix)

- **AI providers** billing/quota (Cerebras 402 etc.) — configure working keys or accept AI skip.
- Some WAFs will still block GitHub runner IPs on DIRECT; Tor fallback remains for that case only when findings stay 0.

## Not regressing

- URL `all.txt` / uro safety path unchanged.
- Crawler critical seeds + waymore from prior commit unchanged.
