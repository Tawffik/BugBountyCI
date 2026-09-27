"""
pipeline/detection/adapters/interactsh.py

Status: not a Python module — documenting an EXISTING integration, not
proposing a new one.

This pipeline already has a real, working Interactsh integration, built
independently of the Detection Engine Framework, in
.github/workflows/zero-track-hunter.yml:

  1. "OOB Setup (Interactsh)" downloads the official prebuilt
     `interactsh-client` binary (pinned release v1.3.1 - verified
     downloadable+runnable, not hand-rolled crypto) and runs it as a
     background process with a persistent session
     (`-ps -psf /tmp/oob/payload.txt -sf /tmp/oob/session.json -json
     -o /tmp/oob/interactions.jsonl`). The assigned base domain (e.g.
     "abc123.oast.fun") is exported as $OOB_DOMAIN.
  2. Any phase that wants OOB confirmation for one specific (url,
     param) test computes
       label = md5(f"{url}|{param}|{vuln_class}|{kind}")[:12]
     appends {"label": label, "url": url, "param": param,
     "vuln_class": vuln_class} as one line to
     ai_agent/oob_correlation.jsonl, and fires a real request using
     f"http://{label}.{OOB_DOMAIN}/" as the payload value.
  3. "OOB Check (Interactsh)" (end of the workflow, after every phase
     that might register a label has run) kills the client, reads
     interactions.jsonl, matches each interaction's subdomain prefix
     against oob_correlation.jsonl by label, and writes
     ai_agent/oob_findings.txt with lines like
     "[OOB-CONFIRMED ssrf] <url> via parameter '<param>' <- real
     out-of-band callback from <ip> at <time>" for genuine matches, or
     "(no matching test found - stray/scanner noise?)" for anything
     else that hit the listener.

This is exactly the design ssrf_engine.py's ORIGINAL module docstring
proposed before this file's author found it already existed - see git
history: the first version of ssrf_engine.py's adapter() was a
documented no-op specifically because hand-rolling Interactsh's
registration/AES protocol from scratch, untestable from a sandbox with
no network route to any oast.* server, was judged too risky (this
project's own history - the httpx `-v`/`-silent` conflict, the
tech.json NDJSON bug, the response_diff `or True` bug - is a repeated
lesson about shipping unverified assumptions about an external tool's
protocol). Finding the real thing already built and working meant that
risk didn't need to be taken at all: ssrf_engine.py's adapter() now
reuses this exact mechanism (same label formula, same
oob_correlation.jsonl file, same "OOB Check" step with ZERO changes
needed there since it matches by label content, not by which phase
wrote it).

Lesson worth keeping, generalized: before building new
verification/escalation infrastructure for a new engine, grep the
workflow for what already exists (`grep -n "interactsh\\|oob_"
.github/workflows/zero-track-hunter.yml` is what surfaced this) - the
same rule that caught the duplicate IDOR engine earlier in this
project's history (docs/V2_ROADMAP.md's "Process lessons" section).
"""
