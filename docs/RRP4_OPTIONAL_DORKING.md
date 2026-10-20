# RRP-4 — Optional Dorking job

Isolated from Zero Track hunter so rate limits / scraping do not starve recon.

## Run

Actions → **Optional Dorking (RRP-4)** → Run workflow → set `target`.

Optional repo secret `GITHUB_PAT` for higher GitHub code-search quota (do not commit tokens).

## Outputs

Artifact `dorking-<target>/` with `report.md`, `urls.txt`, `results.json`.

## Relation to Notion Dorks page

Expand `docs/dorks_rrp4_minimal.txt` from curated Notion lists **after** validating each dork does not flood noise.

## Relation to Exposure Intelligence

EI remains the preferred **passive multi-provider** queue (`HUMAN_QUEUE.md`). This job is GitHub/web dork automation only.
