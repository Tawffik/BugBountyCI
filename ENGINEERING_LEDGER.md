# BugBountyCI Engineering Ledger

## HEAD
`see latest main` — Representation CLOSED at 6c702aa; catalog/sanitize follow-up

## Representation Differential — CLOSED (PROVEN)

**Live verification:** run `37408543776` (#128) · SHA `6c702aa` · target `nuva.finance` · light · `ubuntu-latest` (Sengi quota exhausted interim)

| Metric | Value |
|--------|--------|
| candidates | 7 |
| pairs_run | 7 |
| NO_DIFFERENTIAL / SAME_REPRESENTATION | 5 (app.nuva.finance vaults/referral — real HTTP 200/302) |
| NETWORK_ERROR | 2 (api.* URLError from GitHub egress) |
| Hunter representation entries | 0 (correct — no meaningful differential) |
| Source | `detection/parameter_intelligence.json` primary |

**Contract lessons locked in:**
1. Relative API paths bind to ordered in-scope hosts (never external).
2. Scope rejects google/cdn.
3. Discovery noise (robots/sitemap/.well-known) excluded.
4. Dual transport failure → `NETWORK_ERROR` (not CLEAN).
5. Must read `parameter_intelligence.json` because Representation runs **before** `write_pipeline_exports` writes `meta/endpoints.jsonl`.
6. `NO_CANDIDATES` / `NO_DIFFERENTIAL` / `NETWORK_ERROR` are distinct — never collapse to clean.

**Historical regression:** still CLOSED — 40 REDIRECTED validations → Hunter Queue.

**Runner:** interim `ubuntu-latest`; preserve `NETWORK_MODE=direct_then_tor`. Revert `runs-on` to `sengi-standard-2-ubuntu-2404` when Sengi minutes reset.

## Known limitations
- Target SPA often returns same HTML for Accept html/json → NO_DIFFERENTIAL is expected.
- `api.*` hosts frequently NETWORK_ERROR from GitHub-hosted runners.
- `js_deep/linkfinder_endpoints.txt` is mostly relative chunk paths, not HTTP API routes.
- `response_clusters` empty when `smart-fuzzing/response_diffs.json` is empty.
- Nuclei PARTIAL (~51% error rate) on GitHub egress — truthful DEGRADED health.

## Next ready work (priority)
1. **API catalog / OpenAPI surface** — e.g. `nuva.finance/api-catalog.json` observed in cariddi; strengthen API_HINT for catalog/openapi/swagger (offline first).
2. **LinkFinder normalization** — parse `[js] path` format into usable absolute in-scope URLs where path is real route, not only `./chunk.js`.
3. **response_clusters starvation** — why smart-fuzzing emits empty `response_diffs.json` in light mode (offline forensic).
4. **Nuclei track separation** — keep DEGRADED truthful; avoid blocking core intelligence.
5. Restore Sengi when quota available (egress quality).

## Anti-pattern note
Do not debug Representation with serial 2-hour live runs. Prefer offline replay of harvested artifacts + unit tests, then one live verify.
