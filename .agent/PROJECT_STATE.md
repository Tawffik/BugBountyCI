# BugBountyCI — PROJECT STATE

## MODE
CONTINUE — historical prefer-https **merged** to main; live verify pending

## MAIN
Runtime includes prefer-https historical validation (merged via PR #3).
Prior code tip also has: phase enrichment (`c1d752e`), AI→DEGRADED (`cc311e3`), flags (`3ed22d8`), hostname_targets (`cc51e84`).

## HISTORICAL VALIDATION
- Prefer HTTPS when observed on current surface (not first-seen HTTP lock).
- HTTP fallback when no HTTPS evidence.
- Counters: `scheme_only_skipped`, `validated_substantive` (documented; not vuln counts).
- Offline: tests EXIT 0; #144 dry replay → https validation URLs.
- **Live on merge SHA: NOT YET RUN** (authorized light run still required).

## LAST LIVE PROOF (pre-merge runtime)
#144 `37961580167` capital.com SHA `3ed22d8` success
- hostname_targets=30; engine_health flags populated
- historical: 40 REDIRECTED (http validation URLs) / 63 NOT_RUN — motivated prefer-https fix

## #144 STATUS
**completed success** (ledger mid-gate text that said in_progress is superseded)

## BOUNDARY
BugBountyCI recon producer only. No SRA merge. Nuclei bulk → VulnRadar.
