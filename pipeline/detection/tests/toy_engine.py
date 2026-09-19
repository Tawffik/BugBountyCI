#!/usr/bin/env python3
"""
pipeline/detection/tests/toy_engine.py

A deliberately trivial engine (open-redirect-shaped, but not a real
implementation) whose only job is proving the DetectionEngine interface
actually works end-to-end: prerequisites -> candidates -> detect ->
adapter -> verify -> classify -> written output. Not wired into any
workflow. Do not treat this as a real Open Redirect Engine — see the
project's own Open Redirect spec for what that would actually need
(genuine redirect-following, external-vs-internal destination analysis,
etc.), none of which is here.
"""
from pipeline.detection.engine import DetectionEngine, Candidate, Evidence

REDIRECT_PARAM_HINTS = {"redirect", "url", "next", "return", "returnurl", "continue", "destination"}


class ToyOpenRedirectEngine(DetectionEngine):
    name = "toy-open-redirect"

    def __init__(self, prober=None):
        # Injecting the "prober" is what makes this testable without any
        # real network access: a real engine would default this to an
        # actual HTTP call, tests substitute a fake one.
        self.prober = prober or self._default_prober

    def prerequisites(self, target_profile: dict) -> bool:
        return bool(target_profile.get("hosts"))

    def generate_candidates(self, target_profile: dict, vocabulary: dict) -> list:
        redirect_words = [w for w in vocabulary if w in REDIRECT_PARAM_HINTS]
        if not redirect_words:
            return []
        candidates = []
        for host in target_profile.get("hosts", []):
            for word in redirect_words:
                candidates.append(Candidate(
                    target=f"{host}/?{word}=https://evil.example",
                    engine=self.name,
                    evidence_sources=vocabulary.get(word, {}).get("sources", []),
                    metadata={"parameter": word},
                ))
        return candidates

    def detect(self, candidate: Candidate):
        result = self.prober(candidate.target)
        if result is None:
            return None
        location = result.get("location", "")
        if "evil.example" in location:
            return Evidence(
                candidate=candidate, classification="LEAD",
                reason=f"redirect Location header echoes the injected external host: {location}",
                details=result,
            )
        return None

    def _default_prober(self, url):
        # Real engine would do an HTTP request with redirects disabled
        # and read the Location header. No network access here by design.
        return None
