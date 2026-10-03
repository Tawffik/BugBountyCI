# bugbountyci.response_ranking.v2

Written by `pipeline/smart-fuzzing/response_diff.py` to
`smart-fuzzing/response_ranking.json`.

## Classes (observational, not vulnerabilities)
| Class | Meaning |
|-------|---------|
| AUTH_REQUIRED | 401/407 vs successful baseline |
| REDIRECT | 3xx vs baseline |
| SERVER_ERROR | 5xx vs baseline |
| WAF_BLOCK | 403/406/429/493 after 2xx baseline |
| INTERESTING | other meaningful status/length/content-type delta |
| SPA_FALLBACK | body fingerprint match (requires body capture) |
| DUPLICATE | near-identical hit already seen on host |
| NOISE | close to baseline |
| UNKNOWN | no host baseline |

`waf_dominated: true` when WAF_BLOCK >= 50% of hits — adaptive note for hunters.
