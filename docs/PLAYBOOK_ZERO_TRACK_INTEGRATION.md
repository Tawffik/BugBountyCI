# Playbook ↔ Zero Track Integration Map

**Source:** [Bug Bounty Hunting Playbook — High-Signal Tips & Tricks](https://app.notion.com/p/406dac31e88081d5925ee3b5a3c54ef1) (2026-10-27)  
**Tips index:** [Tips & Tricks INDEX](https://app.notion.com/p/402dac31e8808177a204c67f015a3b21)

Goal: pipeline quality that **supports** quiet high-signal hunting (GitHub, archive, JS, exposure, cloud) — not replace human validation.

| Playbook priority | Playbook section | Zero Track stage / artifact | Integration status |
|-------------------|------------------|----------------------------|--------------------|
| P1 | §2–3 GitHub dorking | `run_github_exposure_slice.py` + existing `github_recon` → `github_exposure/` + desk | **Wired** |
| P1 | §5 Wayback mining | Historical pivot/validation + URL wayback | **Existing** |
| P1 | §4 JS + source maps | JS deep + derived `.map` probes + desk | **Existing + P1a** |
| P1 | §6 Backup/config | Info disclosure paths + derived backup siblings | **Expanded paths** |
| P1 | §6 Subdomain / 404 | Live + content discovery + error_disclosure | **Partial** |
| P2 | §8 S3/cloud | Cloud Exposure V1 | **Existing** |
| P2 | §11 Prometheus/debug | Path probes `/metrics`, `/debug/pprof/`, healthy | **Added** |
| P2 | §12 Swagger/OpenAPI | Existing swagger step + path probes | **Existing + paths** |
| P2 | §7 Google dorks | Optional dorking workflow only (not default hunter) | **Optional** |
| P2 | §13 IDOR/API auth | AC / IDOR AI / hunter LEADs — human proof | **Signal only** |
| P3 | §14–15 OR/SSRF | Existing engines — LEAD not confirmed | **Existing** |

## Operator flow (integrated)

```text
GATE_0
  → DISCLOSURE_DESK (rollup: paths, secrets, maps, github slice, historical, cloud, derived)
  → SECRETS_REVIEW / EXPOSURE_QUEUE
  → hunter_queue.md
  → manual validation (Signal → Ownership → Validation → Impact)
```

## Contracts (from playbook + Blueprint)

- Authorized scope only  
- Search hit ≠ vulnerability  
- Never use discovered secrets to log in  
- LEAD / review queues — no auto CONFIRMED from path or dork  
- Optional dorking is **not** default Hunter input  

## Still human / not fully automated

- Org-only GitHub queries when TARGET is not a GH org  
- Google HTML dorks at scale  
- Firebase/Supabase auth logic chains  
- Full IDOR with two accounts  
- Commit-history deep secret recovery  

