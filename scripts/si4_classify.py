#!/usr/bin/env python3
"""SI-4: context/classification for secret candidates (explainable, no CONFIRMED).

Operates on bugbountyci.secret_candidates.v1 output from SI-2.
Does not claim currentness, capability, or exploitability.
Does not feed Hunter Queue.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def classify_candidate(c: dict) -> dict:
    """Return enriched candidate with SI-4 fields (deterministic)."""
    rules = [str(r) for r in (c.get("rules") or [])]
    match_ref = str(c.get("match_ref") or "")
    detectors = list(c.get("detectors") or [])
    # extract len from match_ref "rule:len=N:fp=..."
    mlen = 0
    m = re.search(r":len=(\d+):", match_ref)
    if m:
        mlen = int(m.group(1))

    candidate_type = "unknown"
    provider = "unknown"
    context_signals: list[str] = []
    benign_indicators: list[str] = []
    explainable_reasons: list[str] = []
    classification_state = c.get("classification") or "LEAD"
    confidence = float(c.get("confidence") or 0.4)

    rule_l = " ".join(rules).lower()

    # --- google reCAPTCHA site key (public by design) ---
    if "google_captcha" in rule_l or "recaptcha" in rule_l:
        candidate_type = "public_client_identifier"
        provider = "google_recaptcha"
        context_signals.append("secretfinder_rule:google_captcha")
        benign_indicators.append("recaptcha_site_keys_are_public_by_design")
        explainable_reasons.append("Google reCAPTCHA site key is intended for client-side use")
        classification_state = "LIKELY_BENIGN"
        confidence = 0.25

    # --- Twilio Account SID shape (true SIDs start with AC) ---
    elif "twilio" in rule_l:
        provider = "twilio"
        context_signals.append("secretfinder_rule:twilio_account_sid")
        if mlen == 34:
            context_signals.append("length_34")
        # Without raw value we cannot verify AC prefix; capital #134 prefixes were not AC
        # fingerprint-only: treat single-detector Twilio SID as weak public-id candidate
        candidate_type = "provider_shaped_identifier"
        benign_indicators.append("client_js_often_embeds_public_account_sid")
        explainable_reasons.append("Twilio Account SID is often public in client SDKs; Auth Token is the secret")
        classification_state = "LEAD"
        confidence = 0.35
        if len(detectors) >= 2:
            classification_state = "HIGH_SIGNAL"
            confidence = 0.7
            explainable_reasons.append("multi_detector_corroboration")

    # --- possible_Creds: capital #134 shows large JS fragments matching 'pass' ---
    elif "possible_cred" in rule_l:
        context_signals.append("secretfinder_rule:possible_Creds")
        if mlen >= 80:
            candidate_type = "code_fragment"
            context_signals.append(f"value_len>={mlen}")
            benign_indicators.append("long_value_likely_minified_js_snippet")
            explainable_reasons.append("SecretFinder possible_Creds often matches password-related identifiers inside JS, not isolated secrets")
            classification_state = "LIKELY_BENIGN"
            confidence = 0.2
        elif mlen <= 12:
            candidate_type = "credential_shaped"
            context_signals.append("short_value")
            explainable_reasons.append("short possible_Creds may be weak credential-shaped; needs human context")
            classification_state = "LEAD"
            confidence = 0.4
        else:
            candidate_type = "credential_shaped"
            explainable_reasons.append("possible_Creds mid-length; insufficient context for benign/strong")
            classification_state = "LEAD"
            confidence = 0.35

    # --- Mantra ---
    elif any(d == "Mantra" for d in detectors) or "mantra" in rule_l:
        candidate_type = "token_like"
        provider = "unknown"
        context_signals.append("detector:Mantra")
        explainable_reasons.append("Mantra token-like observation; often empty or public client tokens on static hosts")
        if mlen < 8:
            classification_state = "LIKELY_BENIGN"
            confidence = 0.2
            benign_indicators.append("very_short_token_value")
        else:
            classification_state = "LEAD"
            confidence = 0.35

    # --- multi-detector generic ---
    elif len(detectors) >= 2:
        candidate_type = "credential_shaped"
        classification_state = "HIGH_SIGNAL"
        confidence = min(0.85, 0.4 + 0.15 * (len(detectors) - 1))
        context_signals.append("multi_detector")
        explainable_reasons.append("corroborated by multiple detectors")
    else:
        candidate_type = "unknown"
        classification_state = "LEAD"
        explainable_reasons.append("single_detector_insufficient_context")

    # Never escalate to CONFIRMED in SI-4
    if classification_state == "CONFIRMED":
        classification_state = "HIGH_SIGNAL"

    out = dict(c)
    out["classification"] = classification_state
    out["confidence"] = confidence
    out["candidate_type"] = candidate_type
    out["provider"] = provider
    out["context_signals"] = context_signals
    out["benign_indicators"] = benign_indicators
    out["explainable_reasons"] = explainable_reasons
    out["si4"] = True
    return out


def classify_report(report: dict) -> dict:
    cands = [classify_candidate(c) for c in report.get("candidates") or []]
    by_class: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for c in cands:
        by_class[c["classification"]] = by_class.get(c["classification"], 0) + 1
        by_type[c.get("candidate_type") or "unknown"] = by_type.get(c.get("candidate_type") or "unknown", 0) + 1
    out = dict(report)
    out["candidates"] = cands
    out["by_class"] = by_class
    out["by_candidate_type"] = by_type
    out["si4"] = True
    out["schema"] = "bugbountyci.secret_candidates.v1+si4"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="SI-2 secret_candidates.json")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    report = json.loads(Path(args.input).read_text())
    out = classify_report(report)
    Path(args.out).write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps({"by_class": out["by_class"], "by_candidate_type": out.get("by_candidate_type"), "n": len(out["candidates"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
