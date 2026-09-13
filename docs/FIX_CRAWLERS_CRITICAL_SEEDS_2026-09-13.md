# Fix: Crawlers + Critical Seeds + Waymore (2026-09-13)

Compared run 25 (strong) vs run 65 (weak crawlers / dropped high-value hosts).

## Changes in `zero-track-hunter.yml`

1. **Critical host seeds (additive)**  
   Always inject into crawl/live lists: apex, `www`, `onlinedoctor`, `photo`, `api`, `app` for `${TARGET}`.  
   New hosts remain; seeds are **not** a replacement.

2. **Crawler recovery**  
   - Longer timeouts (katana 360s, hakrawler 180s, gospider 240s, depth 3)  
   - Crawl input = expensive_targets ∪ critical_seeds  
   - If Tor yield is weak → **DIRECT** retry for that crawler only

3. **waymore**  
   - `pip install waymore`  
   - Passive URL harvest merged into `urls/all.txt` as source `waymore`

4. **AI admin FP**  
   - `/admin`/`/dashboard` hits tagged `AI-ADMIN-CANDIDATE` or `AI-ADMIN-LEAD-SPA` (SPA shell demoted)

5. **Subzy**  
   - Keep VULNERABLE lines; log raw vs kept counts

6. **URL Collection** step budget **30 minutes**

## Not changed

- URL merge / `uro` safety path for `all.txt`  
- Nuclei / ASN (separate workstreams)
