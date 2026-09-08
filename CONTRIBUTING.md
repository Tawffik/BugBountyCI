# Contributing to Zero Track

Thanks for your interest in improving this project.

## Principles

1. **Reliability over feature count** — a scanner that finishes with correct artifacts beats three that produce empty files.
2. **Interesting-first** — new scan steps should consume `results/.../live/scan_order.txt` (fallback: `live.txt`), not only the apex domain.
3. **Triage-friendly output** — prefer high-confidence files (`secrets_high.txt`, ranked hosts) over unbounded greps.
4. **Real-run evidence** — if you fix a failure mode, document the symptom you saw (empty file, exit code, log line).

## Development workflow

1. Fork and branch from `main`.
2. Keep changes focused (one concern per PR when possible).
3. The main workflow is large (`.github/workflows/zero-track-hunter.yml`). Prefer surgical edits; avoid drive-by reformatting.
4. Test with **Actions → Run workflow** on a domain you are authorized to scan (or a deliberately safe lab target).
5. Attach notes: target class, what improved, artifact paths that changed.

## Adding a new scan step

Checklist:

- [ ] `continue-on-error: true` unless failure must abort the job
- [ ] Explicit timeout
- [ ] Writes under `results/${TIMESTAMP}/...`
- [ ] Uses Tor/proxy consistently with neighboring steps when contacting the target
- [ ] Uses `scan_order.txt` when iterating hosts
- [ ] Creates empty output files even on skip (so downstream `wc`/`cat` do not error)
- [ ] Logs under `results/.../logs/`

## Code of conduct (short)

- Only discuss and test **authorized** targets in issues/PRs.
- Do not share live credentials, customer data, or exploit payloads aimed at third parties.
- Be respectful in review discussions.

## Questions

Open an issue with:

- What you expected
- What happened (run URL if possible)
- Relevant log snippets from the artifact (redact secrets)
