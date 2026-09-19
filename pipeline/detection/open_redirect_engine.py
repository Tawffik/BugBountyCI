#!/usr/bin/env python3
"""
pipeline/detection/open_redirect_engine.py

Second real engine on the Detection Engine Framework (after
AccessControlEngine). Supersedes the toy_engine.py proof-of-concept with
a real implementation.

Candidates come from vocabulary.py's evidence-tracked words (redirect/
url/next/return/returnurl/continue/destination) — only tested if the
application itself exposed a parameter matching one of these, per the
project's "generate only candidates supported by application evidence"
rule (never blind-guess every parameter on every endpoint).

Verification distinguishes internal vs external redirect (spec section
29): a Location header pointing back at the same host, or a relative
path, is NOT a signal — only a Location that echoes the injected
external canary domain counts, and even then only LEAD until replay
confirms it's reproducible.

Safety: uses a fixed, non-resolving canary domain
(open-redirect-check.invalid — RFC 2606 .invalid TLD, guaranteed never
to resolve) so this never actually sends traffic anywhere real, and
never follows the redirect (-L is NOT used) — only the Location header
is inspected, nothing is fetched from it.
"""
from __future__ import annotations

from typing import Callable, Optional
from urllib.parse import urlsplit, urlunsplit, quote

from pipeline.detection.engine import Candidate, DetectionEngine, Evidence

REDIRECT_PARAM_HINTS = {"redirect", "redirecturl", "url", "next", "return",
                         "returnurl", "continue", "destination", "callback", "goto"}

# RFC 2606 reserved TLD - guaranteed to never resolve on the real
# internet. Safe to put in a Location header check: nothing ever
# connects to it, this engine only ever reads the response header.
CANARY_HOST = "open-redirect-check.invalid"
CANARY_URL = f"https://{CANARY_HOST}/"


class OpenRedirectEngine(DetectionEngine):
    name = "open-redirect-v1"

    def __init__(self, prober: Optional[Callable[[str], Optional[dict]]] = None,
                 max_candidates: int = 60):
        self.prober = prober or self._no_network_prober
        self.max_candidates = max_candidates

    def _no_network_prober(self, url: str) -> Optional[dict]:
        return None  # no accidental live traffic without an explicit prober

    def prerequisites(self, target_profile: dict) -> bool:
        return bool(target_profile.get("hosts"))

    def generate_candidates(self, target_profile: dict, vocabulary: dict) -> list[Candidate]:
        redirect_words = [w for w in vocabulary if w in REDIRECT_PARAM_HINTS]
        if not redirect_words:
            return []  # no application evidence -> zero candidates, not a guess

        candidates = []
        for host in target_profile.get("hosts", []):
            for word in redirect_words:
                target = f"{host.rstrip('/')}/?{word}={quote(CANARY_URL, safe='')}"
                candidates.append(Candidate(
                    target=target,
                    engine=self.name,
                    evidence_sources=vocabulary.get(word, {}).get("sources", []),
                    metadata={"parameter": word, "host": host},
                ))
                if len(candidates) >= self.max_candidates:
                    return candidates
        return candidates

    def _classify_location(self, location: str, host: str) -> tuple[bool, str]:
        """Returns (is_external_redirect, reason)."""
        if not location:
            return False, "no Location header present"
        loc = location.strip()
        if loc.startswith("/") and not loc.startswith("//"):
            return False, f"redirect target is a relative internal path ({loc}), not external"

        parts = urlsplit(loc if "://" in loc else f"//{loc}")
        target_host = parts.netloc
        origin_host = urlsplit(host if "://" in host else f"//{host}").netloc

        if not target_host:
            return False, "Location header did not parse to a host"
        if target_host == origin_host:
            return False, f"redirect target host ({target_host}) matches the origin — internal, not external"
        if CANARY_HOST in target_host:
            return True, f"Location redirects to the injected external canary host ({target_host})"
        return False, f"Location redirects externally but NOT to our canary ({target_host}) — unrelated redirect, not evidence of injection"

    def detect(self, candidate: Candidate) -> Optional[Evidence]:
        result = self.prober(candidate.target)
        if result is None:
            return None

        status = result.get("status")
        if not status or not (300 <= status < 400):
            return None  # not even a redirect response — nothing to evaluate

        is_external, reason = self._classify_location(
            result.get("location", ""), candidate.metadata.get("host", "")
        )
        if not is_external:
            return Evidence(candidate=candidate, classification="NOISE", reason=reason,
                             details={"status": status, "location": result.get("location")})

        # A single observation of an external, canary-matching redirect
        # is a LEAD at most — verify() is what can promote it further,
        # and only with replay evidence (same discipline as AccessControlEngine).
        return Evidence(candidate=candidate, classification="LEAD", reason=reason,
                         details={"status": status, "location": result.get("location")})

    def verify(self, evidence: Evidence) -> Evidence:
        if evidence.classification != "LEAD":
            return evidence

        replay_results = [self.prober(evidence.candidate.target) for _ in range(2)]
        if any(r is None for r in replay_results):
            evidence.stable = None
            evidence.reason += "; replay incomplete (prober returned nothing) — confidence not raised"
            return evidence

        all_external_to_canary = all(
            self._classify_location(r.get("location", ""), evidence.candidate.metadata.get("host", ""))[0]
            for r in replay_results
        )
        evidence.stable = all_external_to_canary

        if all_external_to_canary:
            evidence.classification = "HIGH_SIGNAL"
            evidence.reason += "; stable across 2 replays, consistently redirects to the external canary — HIGH_SIGNAL"
        else:
            evidence.reason += "; unstable across replay — NOT promoted, confidence lowered"
        return evidence
