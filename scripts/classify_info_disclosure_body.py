#!/usr/bin/env python3
"""Conservative fixed-path response-body classifier for Information Disclosure.

Distinguishes path leads from content-supported candidates. Never promotes
status/path alone to confirmed exposure or confirmed vulnerability.

Dispositions (reason codes):
  PATH_LEAD              — no body available; path/status only
  CONTENT_SUPPORTED      — body matches expected artifact structure
  PLACEHOLDER_ONLY       — env-like but only placeholder values
  SPA_CATCHALL           — SPA/generic HTML catch-all
  WAF_CHALLENGE          — bot/WAF challenge page
  AUTH_WALL              — login/auth wall
  REDIRECT_HINT          — body/meta indicates auth redirect (when provided)
  EMPTY_BODY             — empty or near-empty body
  MALFORMED              — contradicts expected format
  INCONCLUSIVE           — signals conflict or truncated/weak evidence
  GENERIC_NOISE          — generic JSON/docs mentioning secrets without structure

Classification mapping for observation.v1:
  CONTENT_SUPPORTED -> LEAD (confidence medium) — NOT CONFIRMED
  PATH_LEAD         -> LEAD (confidence low)
  SPA/WAF/AUTH/...  -> RESEARCH_CONTEXT equivalent: classification LEAD suppressed
                      or observed_behavior marks non-exposure; never CONFIRMED
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

# --- patterns ---
_GIT_HEAD = re.compile(r"^(ref:\s*refs/heads/\S+|ref:\s*refs/tags/\S+|[0-9a-f]{40})\s*$", re.I | re.M)
_GIT_CONFIG = re.compile(r"\[core\]|\[remote\s+[\"']?\w+[\"']?\]|repositoryformatversion\s*=", re.I)
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S+", re.M)
_PLACEHOLDER = re.compile(
    r"(YOUR_API_KEY_HERE|YOUR_TOKEN_HERE|CHANGEME|xxx_api_key|example_secret|TODO_SECRET|<password>|\$\{[A-Z_]+\})",
    re.I,
)
_SPA = re.compile(
    r"<!DOCTYPE\s+html|<html[\s>]|id=[\"']root[\"']|id=[\"']app[\"']|"
    r"<div[^>]+id=[\"']root[\"']|ng-app=|data-reactroot|__NEXT_DATA__|"
    r"<script[^>]+src=[\"'][^\"']*(?:bundle|app|main|chunk)",
    re.I,
)
_WAF = re.compile(
    r"attention required|checking your browser|cf-browser-verification|"
    r"cloudflare|access denied|request blocked|akamai|imperva|sucuri|"
    r"bot detection|captcha|hcaptcha|recaptcha|please enable javascript.*continue",
    re.I,
)
_AUTH = re.compile(
    r"<form[^>]+(?:login|signin|auth)|name=[\"']password[\"']|"
    r"sign\s*in|log\s*in|authentication required|401 unauthorized|"
    r"www-authenticate|oauth|sso/login",
    re.I,
)
_BACKUP_BIN = re.compile(r"^(PK|\x1f\x8b)|SQLite format|MySQL dump|PostgreSQL database dump|INSERT INTO|CREATE TABLE", re.I | re.M)
_AWS_CREDS = re.compile(r"\[default\]|aws_access_key_id\s*=|aws_secret_access_key\s*=", re.I)
_DOC_MENTION = re.compile(r"\.git/config|\.env\b|git clone", re.I)


def classify_fixed_path_body(
    path_hint: str,
    body: Optional[str] = None,
    *,
    status_code: Optional[int] = None,
    content_type: Optional[str] = None,
    body_truncated: bool = False,
) -> Dict[str, Any]:
    """Classify a fixed-path probe response.

    Returns dict with keys: disposition, confidence, reasons (list[str]),
    expected_family, body_len, never_confirmed (always True for this classifier).
    """
    path = (path_hint or "").lower()
    reasons: list[str] = []
    family = _path_family(path)

    if body is None:
        return _result("PATH_LEAD", "low", ["body_not_available", f"family={family}"], family)

    text = body if isinstance(body, str) else str(body)
    # normalize null bytes for text checks
    sample = text[:8192]
    blen = len(text)
    reasons.append(f"body_len={blen}")
    if body_truncated:
        reasons.append("body_truncated")

    if blen == 0 or (blen < 3 and not sample.strip()):
        return _result("EMPTY_BODY", "low", reasons + ["empty_or_near_empty"], family)

    # Conflicting HTML/WAF/SPA signals first (override weak keyword matches)
    if _WAF.search(sample):
        return _result("WAF_CHALLENGE", "medium", reasons + ["waf_or_bot_challenge_fingerprint"], family)
    if _AUTH.search(sample) and not _looks_like_env(sample) and not _GIT_HEAD.search(sample):
        # auth form HTML
        if _SPA.search(sample) or "<html" in sample.lower() or content_type and "html" in (content_type or "").lower():
            return _result("AUTH_WALL", "medium", reasons + ["login_or_auth_wall_fingerprint"], family)

    if _SPA.search(sample) or (content_type and "html" in content_type.lower() and family in ("git", "env", "backup", "aws")):
        # HTML body for non-HTML expected artifacts
        if family in ("git", "env", "backup", "aws", "config") and (
            _SPA.search(sample) or re.search(r"<!DOCTYPE\s+html|<html[\s>]", sample, re.I)
        ):
            return _result("SPA_CATCHALL", "medium", reasons + ["html_spa_for_expected_non_html_path"], family)

    # Family-specific positive structure
    if family == "git_head":
        if _GIT_HEAD.search(sample.strip().splitlines()[0] if sample.strip() else ""):
            return _result("CONTENT_SUPPORTED", "medium", reasons + ["git_head_ref_or_sha"], family)
        if _SPA.search(sample) or "<html" in sample.lower():
            return _result("SPA_CATCHALL", "medium", reasons + ["html_not_git_head"], family)
        if _DOC_MENTION.search(sample) and not _GIT_HEAD.search(sample):
            return _result("GENERIC_NOISE", "low", reasons + ["docs_mention_without_git_head"], family)
        return _result("MALFORMED", "low", reasons + ["not_plausible_git_head"], family)

    if family == "git_config":
        if _GIT_CONFIG.search(sample) and not _SPA.search(sample):
            return _result("CONTENT_SUPPORTED", "medium", reasons + ["git_config_structure"], family)
        if _SPA.search(sample) or "<html" in sample.lower():
            return _result("SPA_CATCHALL", "medium", reasons + ["html_not_git_config"], family)
        if _DOC_MENTION.search(sample) and not _GIT_CONFIG.search(sample):
            return _result("GENERIC_NOISE", "low", reasons + ["docs_mention_without_git_config"], family)
        return _result("MALFORMED", "low", reasons + ["not_git_config_structure"], family)

    if family == "env":
        if _PLACEHOLDER.search(sample) and not _has_non_placeholder_env(sample):
            return _result("PLACEHOLDER_ONLY", "medium", reasons + ["placeholder_env_values_only"], family)
        if _looks_like_env(sample) and not _SPA.search(sample):
            return _result("CONTENT_SUPPORTED", "medium", reasons + ["env_assignment_structure"], family)
        if _SPA.search(sample) or "<html" in sample.lower():
            return _result("SPA_CATCHALL", "medium", reasons + ["html_not_env"], family)
        return _result("INCONCLUSIVE", "low", reasons + ["env_structure_unclear"], family)

    if family == "aws":
        if _AWS_CREDS.search(sample) and not _SPA.search(sample):
            if _PLACEHOLDER.search(sample) and not re.search(r"AKIA[0-9A-Z]{16}", sample):
                return _result("PLACEHOLDER_ONLY", "medium", reasons + ["aws_block_with_placeholders"], family)
            return _result("CONTENT_SUPPORTED", "medium", reasons + ["aws_credentials_file_structure"], family)
        return _result("INCONCLUSIVE", "low", reasons + ["not_aws_credentials_structure"], family)

    if family == "backup":
        if _SPA.search(sample) or re.search(r"<!DOCTYPE\s+html|<html[\s>]", sample, re.I):
            return _result("SPA_CATCHALL", "medium", reasons + ["html_not_backup"], family)
        if _BACKUP_BIN.search(sample) or (blen > 2048 and not _SPA.search(sample)):
            return _result("CONTENT_SUPPORTED", "medium", reasons + ["backup_or_dump_structure"], family)
        return _result("INCONCLUSIVE", "low", reasons + ["backup_structure_unclear"], family)

    if family == "config":
        if _SPA.search(sample):
            return _result("SPA_CATCHALL", "medium", reasons + ["html_spa_config_path"], family)
        # generic JSON with password word only
        if re.search(r"\{[\s\S]*\}", sample) and re.search(r"password|token", sample, re.I):
            if not re.search(r'"(password|token|secret)"\s*:\s*"[^"]{8,}"', sample):
                return _result("GENERIC_NOISE", "low", reasons + ["json_keyword_without_value_evidence"], family)
        if blen > 20 and not _SPA.search(sample):
            return _result("INCONCLUSIVE", "low", reasons + ["config_body_present_needs_review"], family)
        return _result("INCONCLUSIVE", "low", reasons + ["config_inconclusive"], family)

    # Unknown family
    if _SPA.search(sample):
        return _result("SPA_CATCHALL", "low", reasons + ["spa_fingerprint"], family)
    if body_truncated:
        return _result("INCONCLUSIVE", "low", reasons + ["truncated_unknown_family"], family)
    return _result("INCONCLUSIVE", "low", reasons + ["unknown_family"], family)


def _path_family(path: str) -> str:
    if "/.git/head" in path or path.endswith("git/head") or path.rstrip("/").endswith(".git/head"):
        return "git_head"
    if "/.git/config" in path or path.endswith("git/config"):
        return "git_config"
    if "/.aws/credentials" in path:
        return "aws"
    if "/.env" in path or path.endswith(".env") or ".env." in path:
        return "env"
    if any(x in path for x in (".sql", ".zip", ".tar", ".bak", "backup", "dump")):
        return "backup"
    if any(x in path for x in ("config", "phpinfo", "web.config", "server-status")):
        return "config"
    if "/.git" in path:
        return "git_head"
    return "unknown"


def _looks_like_env(sample: str) -> bool:
    lines = [l for l in sample.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return False
    hits = sum(1 for l in lines[:30] if _ENV_ASSIGN.match(l.strip()))
    return hits >= 1 and hits >= max(1, len(lines[:30]) // 3)


def _has_non_placeholder_env(sample: str) -> bool:
    for m in _ENV_ASSIGN.finditer(sample):
        line = m.group(0)
        if not _PLACEHOLDER.search(line):
            # value side non-empty and not pure placeholder
            if "=" in line:
                val = line.split("=", 1)[1].strip().strip("\"'")
                if val and not _PLACEHOLDER.search(val) and val.lower() not in ("true", "false", "none", "null"):
                    return True
    return False


def _result(disposition: str, confidence: str, reasons: list, family: str) -> Dict[str, Any]:
    return {
        "disposition": disposition,
        "confidence": confidence,
        "reasons": reasons,
        "expected_family": family,
        "never_confirmed": True,
        "is_content_supported": disposition == "CONTENT_SUPPORTED",
        "is_non_exposure": disposition in (
            "SPA_CATCHALL", "WAF_CHALLENGE", "AUTH_WALL", "REDIRECT_HINT",
            "EMPTY_BODY", "GENERIC_NOISE", "PLACEHOLDER_ONLY",
        ),
        "is_path_only": disposition == "PATH_LEAD",
        "needs_review": disposition in ("INCONCLUSIVE", "MALFORMED", "CONTENT_SUPPORTED", "PATH_LEAD"),
    }


def observation_fields_from_classification(clf: Dict[str, Any]) -> Dict[str, Any]:
    """Map classifier output to observation.v1 fields. Never sets CONFIRMED."""
    disp = clf.get("disposition") or "INCONCLUSIVE"
    if clf.get("is_content_supported"):
        return {
            "classification": "LEAD",
            "confidence": "medium",
            "observed_behavior": "content_supported_candidate",
            "detail": f"disposition={disp}; " + ",".join((clf.get("reasons") or [])[:4]),
            "limitations": "Body matches expected structure — not confirmed vulnerability; no auth-boundary proof",
        }
    if clf.get("is_path_only"):
        return {
            "classification": "LEAD",
            "confidence": "low",
            "observed_behavior": "path_lead_body_unavailable",
            "detail": f"disposition={disp}; body not available for classification",
            "limitations": "Path/status only — not content-supported; not confirmed exposure",
        }
    if clf.get("is_non_exposure"):
        return {
            "classification": "LEAD",
            "confidence": "low",
            "observed_behavior": f"non_exposure_{disp.lower()}",
            "detail": f"disposition={disp}; " + ",".join((clf.get("reasons") or [])[:4]),
            "limitations": "Classifier rejected as non-exposure (SPA/WAF/auth/placeholder/noise)",
            # marker for consumers to exclude from INTERESTING promotion
            "_exclude_from_hunter_interesting": True,
        }
    return {
        "classification": "LEAD",
        "confidence": "low",
        "observed_behavior": "inconclusive_body",
        "detail": f"disposition={disp}; " + ",".join((clf.get("reasons") or [])[:4]),
        "limitations": "Ambiguous body — human review; not confirmed exposure",
    }


if __name__ == "__main__":
    # self-check
    assert classify_fixed_path_body("/.git/HEAD", "ref: refs/heads/main\n")["is_content_supported"]
    assert classify_fixed_path_body("/.git/HEAD", None)["disposition"] == "PATH_LEAD"
    assert classify_fixed_path_body("/.env", "<!DOCTYPE html><html><div id='root'>")["disposition"] == "SPA_CATCHALL"
    assert classify_fixed_path_body("/.env", "API_KEY=YOUR_API_KEY_HERE\n")["disposition"] == "PLACEHOLDER_ONLY"
    print("self-check OK")
