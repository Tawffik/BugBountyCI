# Project brief — Zero Track (BugBountyCI)

**One-liner:** GitHub Actions pipeline that automates bug-bounty reconnaissance and vulnerability discovery with host prioritization, Tor-aware reliability, and triage-oriented outputs.

**Audience:** Security engineers, bug bounty hunters, and hiring managers evaluating practical offensive-security automation skills.

**Stack:** GitHub Actions, Bash, Go security toolchain (httpx, nuclei, naabu, katana, …), Python helpers, optional multi-provider LLMs.

**Differentiators:**

- Interesting-host ranking and unified `scan_order` so scanners do not waste budget on apex-only noise
- Production failure fixes (parallel write corruption, Tor concurrency, empty passive URL sources)
- High/low confidence secret classification for usable triage
- End-to-end artifact layout suitable for human review and reporting

**Status:** Active development; main workflow is battle-tested on real authorized targets with iterative fixes from live run evidence.
