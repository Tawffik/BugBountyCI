#!/usr/bin/env python3
"""RRP-1: Build triage/SECRETS_REVIEW.md from existing secret artifact paths.

Purpose
-------
SI deliberately keeps secrets out of Hunter. Operators still need a single
file to open first. This script aggregates high-confidence-looking lines from
js/ and js_deep/ (and optional SI retained JSON) into REVIEW items only.

Contracts
---------
- Never emits classification CONFIRMED.
- Never writes into hunter_queue.
- Redacts secret material in Markdown (prefix only).
- Missing inputs → honest NO_INPUTS / partial, not silent empty success.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "bugbountyci.secrets_review.v1"

# Path / line markers that usually mean fixture or docs noise
NOISE_PATH_RE = re.compile(
    r"(?i)(example|sample|fixture|testdata|mock|dummy|\.md$|/docs/|readme|placeholder|parity)"
)
PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?api[_-]?key|changeme|\bxxx+\b|example_public|do_not_use|"
    r"not_a_real|PLACEHOLDER|\*\*\*|\.\.\.\s*$|AKIAIOSFODNN7EXAMPLE|"
    r"sk_live_\.\.\.|sk_test_\.\.\.|INSERT_|REPLACE_ME|TODO_SECRET)"
)
MODAL_KEYS_RE = re.compile(r"MODAL_KEYS")

# High-signal shape hints (same family as SI-1 baseline; review only)
SHAPE_RES: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_hint", re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]")),
    ("github_pat", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("stripe_sk", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]{8,}){2}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*\S+"
    )),
]


def redact(value: str, keep: int = 6) -> str:
    v = value.strip()
    if len(v) <= keep + 2:
        return "[REDACTED]"
    return v[:keep] + "…[REDACTED]"


def is_noise(path: str, line: str) -> bool:
    if NOISE_PATH_RE.search(path or ""):
        return True
    if PLACEHOLDER_RE.search(line):
        return True
    if MODAL_KEYS_RE.search(line) and "AKIA" not in line:
        return True
    # AWS docs example key
    if "AKIAIOSFODNN7EXAMPLE" in line:
        return True
    return False


def shape_tags(line: str) -> list[str]:
    tags: list[str] = []
    for name, rx in SHAPE_RES:
        if rx.search(line):
            tags.append(name)
    return tags


def add_item(
    items: list[dict[str, Any]],
    *,
    source: str,
    path: str,
    line: str,
    rule: str = "",
) -> None:
    line = line.strip()
    if not line or is_noise(path, line):
        return
    tags = shape_tags(line)
    # Keep generic detector lines only if they carry a shape or explicit rule
    if not tags and not rule:
        # still keep short non-placeholder assignments from secretfinder-style dumps
        if "->" not in line and "=" not in line and ":" not in line:
            return
    items.append(
        {
            "classification": "REVIEW",  # never CONFIRMED
            "source": source,
            "path": path or "",
            "rule": rule or (tags[0] if tags else "raw_line"),
            "shape_tags": tags,
            "line_redacted": redact(line, keep=8) if len(line) > 24 else "[REDACTED]",
            "why_review": (
                "detector/shape observation; human must open context before any report"
            ),
            "next_action": (
                "Open source path in artifact; confirm not example/test; "
                "do not use credentials; follow program disclosure rules"
            ),
        }
    )


def load_text_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        return path.read_text(errors="ignore").splitlines()
    except OSError:
        return []


def ingest_secretfinder(path: Path, items: list[dict[str, Any]]) -> bool:
    if not path.is_file():
        return False
    for line in load_text_lines(path):
        # [file] Rule -> value
        m = re.match(r"\[([^\]]+)\]\s*(.+?)	?->	?(.*)$", line)
        if m:
            f, rule, val = m.group(1), m.group(2).strip(), m.group(3).strip()
            add_item(items, source="secretfinder", path=f, line=f"{rule}={val}", rule=rule)
        else:
            add_item(items, source="secretfinder", path="", line=line)
    return True


def ingest_plain(path: Path, source: str, items: list[dict[str, Any]]) -> bool:
    if not path.is_file():
        return False
    for line in load_text_lines(path):
        add_item(items, source=source, path=str(path.name), line=line)
    return True


def ingest_gitleaks(path: Path, items: list[dict[str, Any]]) -> bool:
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(errors="ignore") or "[]")
    except json.JSONDecodeError:
        return True  # present but unparseable — caller notes via empty contrib
    if isinstance(data, dict):
        data = data.get("findings") or data.get("results") or []
    if not isinstance(data, list):
        return True
    for row in data:
        if not isinstance(row, dict):
            continue
        secret = str(row.get("Secret") or row.get("Match") or "")
        f = str(row.get("File") or row.get("file") or "")
        rule = str(row.get("RuleID") or row.get("rule") or "gitleaks")
        add_item(items, source="gitleaks", path=f, line=secret or rule, rule=rule)
    return True


def ingest_trufflehog(path: Path, items: list[dict[str, Any]]) -> bool:
    if not path.is_file():
        return False
    text = path.read_text(errors="ignore")
    # JSONL or JSON array
    rows: list[Any] = []
    if text.strip().startswith("["):
        try:
            rows = json.loads(text)
        except json.JSONDecodeError:
            rows = []
    else:
        for line in text.splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    add_item(items, source="trufflehog", path="", line=line)
    for row in rows:
        if not isinstance(row, dict):
            continue
        det = row.get("DetectorName") or row.get("Detector") or "trufflehog"
        raw = row.get("Raw") or row.get("RawV2") or row.get("redacted") or ""
        meta = row.get("SourceMetadata") or {}
        f = ""
        if isinstance(meta, dict):
            data = meta.get("Data") or {}
            if isinstance(data, dict):
                f = str((data.get("Filesystem") or {}).get("file") or "")
        add_item(
            items,
            source="trufflehog",
            path=f,
            line=str(raw) or str(det),
            rule=str(det),
        )
    return True


def ingest_si_candidates(path: Path, items: list[dict[str, Any]]) -> bool:
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(errors="ignore") or "{}")
    except json.JSONDecodeError:
        return True
    cands = data.get("candidates") if isinstance(data, dict) else None
    if not isinstance(cands, list):
        return True
    for c in cands:
        if not isinstance(c, dict):
            continue
        # Only surface retained LEAD/HIGH_SIGNAL style — still REVIEW for humans
        cls = str(c.get("classification") or "")
        if cls.upper() in {"NOISE", "SUPPRESSED"}:
            continue
        add_item(
            items,
            source="si_canonical",
            path=str(c.get("file") or ""),
            line=str(c.get("match_ref") or c.get("candidate_id") or ""),
            rule=",".join(c.get("rules") or []) or "si",
        )
    return True


def dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for it in items:
        key = f"{it.get('source')}|{it.get('path')}|{it.get('rule')}|{it.get('line_redacted')}"
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


def build(results_dir: Path) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    checked: dict[str, bool] = {}

    paths = {
        "js/secrets_high.txt": results_dir / "js" / "secrets_high.txt",
        "js/secrets.txt": results_dir / "js" / "secrets.txt",
        "js_deep/secretfinder_secrets.txt": results_dir / "js_deep" / "secretfinder_secrets.txt",
        "js_deep/mantra_findings.txt": results_dir / "js_deep" / "mantra_findings.txt",
        "js_deep/gitleaks_findings.json": results_dir / "js_deep" / "gitleaks_findings.json",
        "js_deep/trufflehog_findings.json": results_dir / "js_deep" / "trufflehog_findings.json",
        "js_deep/trufflehog_findings.jsonl": results_dir / "js_deep" / "trufflehog_findings.jsonl",
        "si/secret_candidates.json": results_dir / "si" / "secret_candidates.json",
        "detection/secret_candidates.json": results_dir / "detection" / "secret_candidates.json",
    }

    checked["js/secrets_high.txt"] = ingest_plain(paths["js/secrets_high.txt"], "secrets_high", items)
    checked["js/secrets.txt"] = ingest_plain(paths["js/secrets.txt"], "secrets_txt", items)
    checked["js_deep/secretfinder_secrets.txt"] = ingest_secretfinder(
        paths["js_deep/secretfinder_secrets.txt"], items
    )
    checked["js_deep/mantra_findings.txt"] = ingest_plain(
        paths["js_deep/mantra_findings.txt"], "mantra", items
    )
    checked["js_deep/gitleaks_findings.json"] = ingest_gitleaks(
        paths["js_deep/gitleaks_findings.json"], items
    )
    th_json = ingest_trufflehog(paths["js_deep/trufflehog_findings.json"], items)
    th_jsonl = ingest_trufflehog(paths["js_deep/trufflehog_findings.jsonl"], items)
    checked["js_deep/trufflehog"] = th_json or th_jsonl
    checked["si/secret_candidates.json"] = ingest_si_candidates(
        paths["si/secret_candidates.json"], items
    )
    checked["detection/secret_candidates.json"] = ingest_si_candidates(
        paths["detection/secret_candidates.json"], items
    )

    items = dedupe(items)
    # Prefer shaped items first
    items.sort(key=lambda x: (0 if x.get("shape_tags") else 1, x.get("source") or "", x.get("path") or ""))

    present = [k for k, v in checked.items() if v]
    missing = [k for k, v in checked.items() if not v]

    if not present:
        status = "NO_INPUTS"
    elif not items:
        status = "EMPTY_AFTER_FILTER"
    else:
        status = "OK"

    return {
        "schema": SCHEMA,
        "status": status,
        "inputs_present": present,
        "inputs_missing": missing,
        "review_count": len(items),
        "items": items,
        "notes": [
            "classification is REVIEW only — not a confirmed vulnerability",
            "SI→Hunter remains OFF by project policy",
            "Open source paths in the run artifact before any disclosure",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# SECRETS REVIEW (RRP-1)",
        "",
        f"**Status:** `{report['status']}`  ",
        f"**Review items:** {report['review_count']}  ",
        "",
        "> Not CONFIRMED. Not Hunter. Human opens context next.",
        "",
        "## Inputs",
        "",
        "Present: " + (", ".join(f"`{p}`" for p in report["inputs_present"]) or "_(none)_"),
        "",
        "Missing: " + (", ".join(f"`{p}`" for p in report["inputs_missing"]) or "_(none)_"),
        "",
    ]
    if report["status"] == "NO_INPUTS":
        lines += [
            "## Diagnosis",
            "",
            "No secret artifact files were found under this results root.",
            "Check whether JS deep / secrets steps ran, or whether the funnel",
            "starved earlier (`urls/all.txt`, live hosts).",
            "",
        ]
        return "\n".join(lines)

    if report["status"] == "EMPTY_AFTER_FILTER":
        lines += [
            "## Diagnosis",
            "",
            "Input files existed but every line was filtered as placeholder/example/noise.",
            "This is **not** proof the target is safe.",
            "",
        ]
        return "\n".join(lines)

    lines += ["## Review queue", ""]
    for i, it in enumerate(report["items"], 1):
        tags = ", ".join(it.get("shape_tags") or []) or "—"
        lines += [
            f"### {i}. `{it.get('rule')}` ({it.get('source')})",
            f"- **path:** `{it.get('path') or '—'}`",
            f"- **shapes:** {tags}",
            f"- **redacted:** `{it.get('line_redacted')}`",
            f"- **next:** {it.get('next_action')}",
            "",
        ]
    lines += ["## Notes", ""] + [f"- {n}" for n in report.get("notes") or []] + [""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build triage/SECRETS_REVIEW.md (RRP-1)")
    ap.add_argument(
        "--results-dir",
        required=True,
        help="Run results root (contains js/, js_deep/, …)",
    )
    ap.add_argument(
        "--out-dir",
        default="",
        help="Defaults to <results-dir>/triage",
    )
    args = ap.parse_args()
    results = Path(args.results_dir)
    out_dir = Path(args.out_dir) if args.out_dir else results / "triage"
    out_dir.mkdir(parents=True, exist_ok=True)

    report = build(results)
    (out_dir / "secrets_review.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (out_dir / "SECRETS_REVIEW.md").write_text(render_md(report), encoding="utf-8")
    print(
        json.dumps(
            {
                "status": report["status"],
                "review_count": report["review_count"],
                "out": str(out_dir / "SECRETS_REVIEW.md"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
