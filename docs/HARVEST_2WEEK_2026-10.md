# Two-Week Harvest Benchmark — 2026-09-28 → 2026-10-10

**Purpose:** Evidence from completed Zero Track artifacts (not waiting on #145).
**Sample:** #134–#144 cohort with results artifacts still available.

## Historical validation pattern (dominant waste)

| Run | Target | Eligible | Validated | Outcomes | validation_url schemes |
|-----|--------|----------|-----------|----------|------------------------|
| #144 | capital | 103 | 40 | REDIRECTED 40 | http 99 / https 4 |
| #143 | superdrug | 394 | 40 | REDIR 36, BLOCKED 4 | http 394 |
| #141 | capital | 103 | 40 | REDIRECTED 40 | http 99 / https 4 |
| #140 | aikido | 129 | 40 | REDIRECTED 40 | http 113 / https 16 |
| #139 | capital | 103 | 40 | REDIRECTED 40 | http 102 / https 1 |

**Root cause:** first-seen scheme from live.txt preferred **http** → scheme-only 301 to https.
**Fix on main:** PR #3 prefer-https + PR #4 path-priority + PR #5 dry-run budget.
**Live proof:** still pending on a post-#3 SHA (#145 in progress on `56ec797`).

## Hunter operator noise

| Run | Symptom |
|-----|---------|
| #143 | Delta “New interesting hosts (741)” dominated by pure IP:port |
| #144 | Similar IP-heavy delta lines |

**Fix on main:** PR #10 — delta prefers hostnames; reports suppressed pure-IP count. Raw `diff/*` unchanged.

## Host export scale

| Run | hosts.jsonl lines | Note |
|-----|-------------------|------|
| #139 | 14378 | Pre IP-cap |
| #141 | 245 | Post modeling fixes |
| #144 | 274 | Stable |

## Relationships / correlation

| Run | HIST∩JS | JS∩live |
|-----|---------|---------|
| #144 capital | 6 | (in graph) |
| #140 aikido | 34 | 85 |

**Fix on main:** PR #6 boost HIST∩JS to INTERESTING when CURRENTLY_REACHABLE.

## Phase 2 observations

Historical/representation/detection/params were incomplete in `observations.jsonl`.
**Fix on main:** PR #7–#9.

## Explicitly not claimed

- #145 live outcomes
- Phase 3 full object model
- Formal Phase 11 multi-month benchmark suite
- SI→Hunter promotion

**Status:** CONTINUE — offline harvest-driven fixes merged; live tip verification still open.
