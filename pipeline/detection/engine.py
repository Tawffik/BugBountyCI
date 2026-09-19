#!/usr/bin/env python3
"""
pipeline/detection/engine.py — Detection Engine Framework (skeleton)

This is intentionally a skeleton, not a finished framework: it exists to
be validated by ONE real engine before any of SQLi/XSS/SSRF/etc. get
built on top of it. See tests/test_toy_engine.py for a runnable,
end-to-end proof that the interface actually works — not just that it
imports.

Design source: the project's "Detection Engine Framework" spec (section
23) and repository architecture (section 54). Every vulnerability class
becomes an Engine with the same shape:

    prerequisites()      -> does this target even have what this engine needs?
    generate_candidates() -> what's worth testing, based on evidence (not guesses)?
    detect()              -> cheap, deterministic, in-process check
    adapter()             -> OPTIONAL escalation to an external tool (SQLMap,
                             Dalfox, Nuclei, Interactsh...) only when detect()
                             found something worth escalating
    verify()               -> replay/stability check before trusting a signal
    classify()              -> NOISE / LOW_SIGNAL / LEAD / HIGH_SIGNAL /
                                CONFIRMED — never "vulnerability found" from a
                                single response

The orchestrator (run_engine / run_engines) wraps every engine call in a
try/except: one broken or half-implemented engine must never take down
the run, matching the project's existing "continue-on-error, always
have a fallback" philosophy used everywhere else in this pipeline.

This module has ZERO new dependencies (stdlib only) and does not call
any external tool itself — adapters are where a concrete engine would
shell out to something, and this skeleton ships no adapters yet.
"""
from __future__ import annotations

import json
import os
import time
import traceback
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Iterable, Optional

VALID_CLASSIFICATIONS = ("NOISE", "LOW_SIGNAL", "LEAD", "HIGH_SIGNAL", "CONFIRMED")


@dataclass
class Candidate:
    """Something a DetectionEngine wants to test. Deliberately generic —
    a URL+parameter for an injection engine, a path+method for an
    access-control engine, etc. `evidence_sources` is mandatory-in-spirit:
    per the project's core rule, a candidate should trace back to
    something observed (JS/API/parameter/pattern), not a blind guess.
    """
    target: str                      # the URL/endpoint/host being tested
    engine: str                      # which engine produced this, e.g. "sqli"
    evidence_sources: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)  # engine-specific extras

    def to_dict(self):
        return asdict(self)


@dataclass
class Evidence:
    """The output of testing one Candidate. classification is REQUIRED
    and MUST be one of VALID_CLASSIFICATIONS — this is enforced in
    __post_init__ specifically so a future engine can't accidentally
    invent a "VULNERABILITY_FOUND" label, which the project's Golden
    Rule explicitly forbids."""
    candidate: Candidate
    classification: str
    reason: str
    stable: Optional[bool] = None      # set by verify(), None if not replayed
    details: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.classification not in VALID_CLASSIFICATIONS:
            raise ValueError(
                f"Invalid classification {self.classification!r}. Must be one of "
                f"{VALID_CLASSIFICATIONS} — engines must not invent their own labels "
                f"(e.g. never 'VULNERABILITY_FOUND', see the project's Golden Rule)."
            )

    def to_dict(self):
        d = asdict(self)
        d["candidate"] = self.candidate.to_dict()
        return d


class DetectionEngine:
    """Base class every concrete engine (SQLi, XSS, SSRF, ...) subclasses.
    Every method has a safe default so a minimal engine can be written
    with just prerequisites() + generate_candidates() + detect() and
    still run end-to-end — adapter()/verify() are optional escalation
    steps, not requirements.
    """
    name: str = "unnamed-engine"

    def prerequisites(self, target_profile: dict) -> bool:
        """Return False to skip this engine entirely for this target
        (e.g. an SSRF engine with zero url-like parameters observed).
        Default: always eligible — override to actually gate."""
        return True

    def generate_candidates(self, target_profile: dict, vocabulary: dict) -> list[Candidate]:
        """Return Candidates grounded in target_profile/vocabulary. Must
        NOT be implemented as "try every parameter against every
        endpoint" — see the project's Parameter Intelligence rule."""
        raise NotImplementedError

    def detect(self, candidate: Candidate) -> Optional[Evidence]:
        """Cheap, deterministic, in-process check. Return None if
        nothing worth reporting (this is the common case — most
        candidates should produce nothing)."""
        raise NotImplementedError

    def adapter(self, candidate: Candidate, detect_evidence: Evidence) -> Optional[Evidence]:
        """OPTIONAL: escalate to an external tool (SQLMap, Dalfox, Nuclei,
        Interactsh...) only when detect_evidence justifies it. Default:
        no adapter, just return the detect() evidence unchanged."""
        return detect_evidence

    def verify(self, evidence: Evidence) -> Evidence:
        """OPTIONAL: replay/stability check. Default: mark unverified
        (stable=None) rather than silently claiming stability that was
        never actually checked."""
        return evidence


@dataclass
class EngineRunResult:
    engine: str
    ran: bool
    error: Optional[str] = None
    candidates_generated: int = 0
    evidence: list = field(default_factory=list)  # list[Evidence]
    duration_s: float = 0.0

    def to_dict(self):
        d = asdict(self)
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


def run_engine(engine: DetectionEngine, target_profile: dict, vocabulary: dict,
               max_candidates: int = 200) -> EngineRunResult:
    """Run one engine against one target, end to end, with every step
    isolated so a bug in one engine can't take down the batch (or the
    calling pipeline). This mirrors the "continue-on-error, always keep
    a fallback" pattern already used everywhere else in this repo's
    workflow and scripts.
    """
    result = EngineRunResult(engine=engine.name, ran=False)
    start = time.time()
    try:
        if not engine.prerequisites(target_profile):
            result.ran = True
            result.error = "prerequisites not met — skipped (this is expected, not a failure)"
            return result

        candidates = engine.generate_candidates(target_profile, vocabulary)
        candidates = candidates[:max_candidates]  # hard cap: no engine explodes a run
        result.candidates_generated = len(candidates)

        for c in candidates:
            try:
                ev = engine.detect(c)
                if ev is None:
                    continue
                ev = engine.adapter(c, ev) or ev
                ev = engine.verify(ev)
                result.evidence.append(ev)
            except Exception as e:
                # One bad candidate must not stop the rest.
                result.evidence.append(Evidence(
                    candidate=c, classification="NOISE",
                    reason=f"engine raised an exception on this candidate: {e}",
                ))
        result.ran = True
    except Exception:
        result.ran = False
        result.error = traceback.format_exc(limit=3)
    result.duration_s = round(time.time() - start, 3)
    return result


def run_engines(engines: Iterable[DetectionEngine], target_profile: dict, vocabulary: dict,
                 results_dir: str) -> list[EngineRunResult]:
    """Run every given engine and write detection/engine_results.json.
    A single broken engine is recorded (ran=False, error=...) and does
    NOT stop the others from running — matching the pipeline-wide rule
    that one failed module never takes down the run."""
    out_dir = os.path.join(results_dir, "detection")
    os.makedirs(out_dir, exist_ok=True)

    results = []
    for engine in engines:
        results.append(run_engine(engine, target_profile, vocabulary))

    with open(os.path.join(out_dir, "engine_results.json"), "w") as f:
        json.dump([r.to_dict() for r in results], f, indent=2)

    return results
