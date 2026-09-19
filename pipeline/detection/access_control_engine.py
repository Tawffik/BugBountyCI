#!/usr/bin/env python3
"""
pipeline/detection/access_control_engine.py

The first REAL engine built on the Detection Engine Framework
(pipeline/detection/engine.py). Everything before this commit was a toy
used only to validate the framework's interface.

Scope (V1 / Phase 1 only, per the project's own phased order — section
55/62): 401/403 candidates + safe path mutations + response comparison +
replay stability. Explicitly NOT in scope yet: method intelligence,
header intelligence, encoding tricks — those are Phase 2.

Where candidates come from: this engine does NOT re-probe the whole site
looking for protected endpoints. It reads endpoints smart-fuzzing's
response_diff.py already found returning 401/403
(<RD>/smart-fuzzing/response_diffs.json) and treats THAT recorded
response as the "Endpoint Blocked Baseline" (spec section 10.B / 14) —
reusing existing Response Intelligence output rather than duplicating
baseline logic in a new access_control/baseline.py, per the project's
explicit "don't duplicate baseline/response_diff" instruction.

Mutation set: a small, fixed, safe subset (spec section 20) — this is
deliberately NOT an open-ended fuzzer. Extending the mutation list is a
one-line change, not an architecture change.

Golden Rule enforcement: classify() never returns anything above LEAD
unless verify() has actually replayed the mutation and found it stable.
A single 403->200 observation is capped at LEAD, never HIGH_SIGNAL or
CONFIRMED, no matter how different the response looks.
"""
from __future__ import annotations

import json
import os
from typing import Callable, Optional
from urllib.parse import urlsplit, urlunsplit

from pipeline.detection.engine import Candidate, DetectionEngine, Evidence

# Safe, fixed mutation set (spec section 20). Deliberately small — this
# is target-aware selection, not "generate hundreds of permutations".
PATH_MUTATIONS = [
    lambda p: p + "/",
    lambda p: p + "/.",
    lambda p: p + "/./",
    lambda p: p + "?x=1",
    lambda p: "//" + p.lstrip("/"),  # double-slash prefix, e.g. "//admin"
    lambda p: p + "%2f",
    lambda p: p + "%3f",
]

BLOCKED_STATUSES = (401, 403)


def _mutate_url(url: str, mutator) -> Optional[str]:
    parts = urlsplit(url)
    if not parts.path:
        return None
    try:
        new_path = mutator(parts.path)
    except Exception:
        return None
    return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))


class AccessControlEngine(DetectionEngine):
    name = "access-control-v1"

    def __init__(self, results_dir: str, prober: Optional[Callable[[str], Optional[dict]]] = None,
                 max_endpoints: int = 30):
        self.results_dir = results_dir
        self.max_endpoints = max_endpoints
        # Injectable, same pattern as the toy engine: a real prober does
        # an actual HTTP GET with redirects disabled; tests substitute a
        # fake one so this engine is testable without any network access.
        self.prober = prober or self._no_network_prober

    def _no_network_prober(self, url: str) -> Optional[dict]:
        return None  # deliberately does nothing without an explicit prober — no accidental live traffic

    def prerequisites(self, target_profile: dict) -> bool:
        path = os.path.join(self.results_dir, "smart-fuzzing", "response_diffs.json")
        return os.path.isfile(path)

    def generate_candidates(self, target_profile: dict, vocabulary: dict) -> list[Candidate]:
        path = os.path.join(self.results_dir, "smart-fuzzing", "response_diffs.json")
        try:
            with open(path, "r", errors="ignore") as f:
                diffs = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []

        # DUPLICATE-classified hits are the same block page repeated —
        # skip them, one representative per (host, status, ~length)
        # cluster is enough; testing every near-identical duplicate would
        # violate the project's own "don't multiply the same signal"
        # rule that response_diff.py itself was fixed to enforce.
        blocked = [d for d in diffs
                   if d.get("status") in BLOCKED_STATUSES and d.get("classification") != "DUPLICATE"]
        blocked = blocked[: self.max_endpoints]

        candidates = []
        for hit in blocked:
            url = hit.get("url")
            if not url:
                continue
            baseline = {
                "status": hit.get("status"),
                "length": hit.get("length"),
                "content_type": hit.get("content_type"),
            }
            for mutator in PATH_MUTATIONS:
                mutated_url = _mutate_url(url, mutator)
                if not mutated_url or mutated_url == url:
                    continue
                candidates.append(Candidate(
                    target=mutated_url,
                    engine=self.name,
                    evidence_sources=["smart-fuzzing/response_diffs.json"],
                    metadata={"original_url": url, "baseline": baseline},
                ))
        return candidates

    def detect(self, candidate: Candidate) -> Optional[Evidence]:
        baseline = candidate.metadata.get("baseline", {})
        result = self.prober(candidate.target)
        if result is None:
            return None  # prober couldn't reach it — no signal, not a failure worth reporting

        reasons = []
        changed = False

        if result.get("status") != baseline.get("status"):
            reasons.append(f"status {result.get('status')} != blocked-baseline {baseline.get('status')}")
            changed = True

        base_len = max(baseline.get("length") or 0, 1)
        length_diff = abs((result.get("length") or 0) - base_len)
        if length_diff >= max(base_len * 0.15, 200):
            reasons.append(f"length differs by {length_diff} bytes from blocked-baseline")
            changed = True

        base_ct = (baseline.get("content_type") or "").split(";")[0].strip()
        hit_ct = (result.get("content_type") or "").split(";")[0].strip()
        if base_ct and hit_ct and base_ct != hit_ct:
            reasons.append(f"content-type {hit_ct} != blocked-baseline {base_ct}")
            changed = True

        if not changed:
            return Evidence(candidate=candidate, classification="NOISE",
                             reason="mutation response matches the original blocked response",
                             details={"mutation_response": result})

        # A single observed change is a LEAD at most — see module docstring.
        # verify() is what can promote this further, and only with replay evidence.
        return Evidence(candidate=candidate, classification="LEAD",
                         reason="; ".join(reasons), details={"mutation_response": result})

    def verify(self, evidence: Evidence) -> Evidence:
        if evidence.classification != "LEAD":
            return evidence  # NOISE stays NOISE; nothing to verify

        replay_results = [self.prober(evidence.candidate.target) for _ in range(2)]
        if any(r is None for r in replay_results):
            evidence.stable = None
            evidence.reason += "; replay incomplete (prober returned nothing) — confidence not raised"
            return evidence

        statuses = {r.get("status") for r in replay_results}
        lengths = {r.get("length") for r in replay_results}
        stable = len(statuses) == 1 and len(lengths) == 1
        evidence.stable = stable

        if not stable:
            evidence.reason += "; unstable across replay — NOT promoted, confidence lowered"
            return evidence  # stays LEAD, not upgraded

        baseline = evidence.candidate.metadata.get("baseline", {})
        base_len = max(baseline.get("length") or 0, 1)
        result_len = replay_results[0].get("length") or 0
        endpoint_specific = abs(result_len - base_len) >= max(base_len * 0.5, 1000)

        if stable and endpoint_specific:
            evidence.classification = "HIGH_SIGNAL"
            evidence.reason += "; stable across 2 replays with substantial endpoint-specific content — HIGH_SIGNAL"
        else:
            evidence.reason += "; stable but not substantially endpoint-specific — remains LEAD"
        return evidence
