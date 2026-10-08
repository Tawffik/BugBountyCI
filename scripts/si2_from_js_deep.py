#!/usr/bin/env python3
"""js_deep/* → SI-2 observations → canonical secret candidates.

Parses real BugBountyCI detector output shapes. No raw secrets in output.
Does not feed Hunter Queue.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from si2_canonicalize import canonicalize  # type: ignore

MODAL_KEYS_RE = re.compile(r"MODAL_KEYS")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
PLACEHOLDER_RE = re.compile(
    r"(?i)(your_api_key_here|changeme|\bxxx\b|example_public|placeholder|not_a_real|do_not_use)"
)
HEROKU_UUID_LABEL = re.compile(r"(?i)heroku\s*api\s*key")

def _is_js_code_fragment(val: str) -> bool:
    """True when SecretFinder possible_Creds matched a minified JS snippet, not an isolated secret.

    Evidence from capital #134: long values with JS syntax (let/var/;/{} /function/=>).
    Narrow: only applied to possible_Creds by the caller.
    """
    if len(val) < 40:
        return False
    if len(val) >= 80 and (";" in val or "{" in val or "}" in val):
        return True
    if re.search(r"\b(let|var|const|function)\b", val) or "=>" in val:
        return True
    if val.count(";") >= 2:
        return True
    return False



def _fp(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8", errors="replace")).hexdigest()[:24]


def _safe_ref(kind: str, value: str) -> str:
    v = (value or "").strip()
    return f"{kind}:len={len(v)}:fp={_fp(kind, v)}"


def parse_secretfinder(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        src, rest = "", line
        if line.startswith("[") and "]" in line:
            src = line[1 : line.index("]")]
            rest = line[line.index("]") + 1 :].strip()
        parts = re.split(r"\s*->\s*", rest, maxsplit=1)
        if len(parts) == 2:
            typ, val = parts[0].strip(), parts[1].strip()
        else:
            typ, val = "unknown", rest
        if MODAL_KEYS_RE.search(line):
            continue
        if UUID_RE.match(val) and (
            HEROKU_UUID_LABEL.search(typ) or "possible_cred" in typ.lower()
        ):
            continue
        if "possible_cred" in (typ or "").lower() and _is_js_code_fragment(val):
            continue
        if PLACEHOLDER_RE.search(val):
            continue
        # Short authorization_api tokens (often "Bearer "+short) are low-value noise on capital-class JS
        if "authorization" in (typ or "").lower() and len(val) < 24:
            continue
        out.append(
            {
                "detector": "SecretFinder",
                "rule": typ or "secretfinder",
                "file": src,
                "match_ref": _safe_ref(typ or "sf", val),
                "fingerprint": _fp("content", val),
            }
        )
    return out


def parse_gitleaks(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text() or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("RuleID") or "gitleaks")
        file = str(item.get("File") or "")
        secret = str(item.get("Secret") or item.get("Match") or "")
        match = str(item.get("Match") or "")
        if MODAL_KEYS_RE.search(match) or MODAL_KEYS_RE.search(secret):
            continue
        if UUID_RE.match(secret.strip()):
            continue
        if PLACEHOLDER_RE.search(secret):
            continue
        out.append(
            {
                "detector": "Gitleaks",
                "rule": rule,
                "file": file,
                "match_ref": _safe_ref(rule, secret),
                "fingerprint": _fp("content", secret),
            }
        )
    return out


def parse_trufflehog(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        det = str(item.get("DetectorName") or item.get("Detector") or "trufflehog")
        file = ""
        src = item.get("SourceMetadata") or {}
        if isinstance(src, dict):
            data = src.get("Data") or {}
            if isinstance(data, dict):
                fs = data.get("Filesystem") or {}
                if isinstance(fs, dict):
                    file = str(fs.get("file") or "")
        raw = str(item.get("Raw") or item.get("Redacted") or "")
        if PLACEHOLDER_RE.search(raw) or UUID_RE.match(raw.strip()):
            continue
        out.append(
            {
                "detector": "TruffleHog",
                "rule": det,
                "file": file,
                "match_ref": _safe_ref(det, raw),
                "fingerprint": _fp("content", raw),
            }
        )
    return out


def parse_mantra(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line.startswith("[+]"):
            continue
        body = line[3:].strip()
        if PLACEHOLDER_RE.search(body):
            continue
        if re.search(r"\[\w+=\]\s*$", body):
            continue
        out.append(
            {
                "detector": "Mantra",
                "rule": "mantra",
                "file": body.split()[0] if body else "",
                "match_ref": _safe_ref("mantra", body),
                "fingerprint": _fp("content", body),
            }
        )
    return out


def collect_js_deep(results_dir: Path) -> list[dict]:
    jd = results_dir / "js_deep"
    obs: list[dict] = []
    obs.extend(parse_secretfinder(jd / "secretfinder_secrets.txt"))
    obs.extend(parse_gitleaks(jd / "gitleaks_findings.json"))
    obs.extend(parse_trufflehog(jd / "trufflehog_findings.jsonl"))
    obs.extend(parse_mantra(jd / "mantra_findings.txt"))
    return obs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    rd = Path(args.results_dir)
    obs = collect_js_deep(rd)
    cands = canonicalize(obs)
    jd = rd / "js_deep"
    def _nlines(name, pred=None):
        path = jd / name
        if not path.is_file():
            return 0
        lines = path.read_text(errors="ignore").splitlines()
        if pred is None:
            return sum(1 for l in lines if l.strip())
        return sum(1 for l in lines if pred(l))
    raw_line_counts = {
        "secretfinder": _nlines("secretfinder_secrets.txt"),
        "gitleaks": _nlines("gitleaks_findings.json"),  # file may be JSON array; approximate
        "trufflehog": _nlines("trufflehog_findings.jsonl"),
        "mantra": _nlines("mantra_findings.txt", lambda l: l.strip().startswith("[+]")),
    }
    try:
        import json as _json
        glp = jd / "gitleaks_findings.json"
        if glp.is_file():
            raw_line_counts["gitleaks"] = len(_json.loads(glp.read_text() or "[]"))
    except Exception:
        pass
    report = {
        "schema": "bugbountyci.secret_candidates.v1",
        "source": "js_deep",
        "raw_line_counts": raw_line_counts,
        "raw_total": sum(raw_line_counts.values()),
        "observation_count": len(obs),
        "canonical_count": len(cands),
        "hard_negative_or_noise_dropped": sum(raw_line_counts.values()) - len(obs),
        "by_class": {},
        "candidates": cands,
        "note": "No raw secrets stored; fingerprints only. Not fed to Hunter Queue.",
    }
    for c in cands:
        cl = c.get("classification") or "UNKNOWN"
        report["by_class"][cl] = report["by_class"].get(cl, 0) + 1
    out = Path(args.out) if args.out else rd / "meta" / "secret_candidates.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"js_deep_obs={len(obs)} canonical={len(cands)} classes={report['by_class']} -> {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
