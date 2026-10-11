#!/usr/bin/env python3
"""Record bounded, redacted fixed-path probe evidence to probe_results.jsonl."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from typing import Optional

MAX_BODY_BYTES = 2048
MAX_READ_BYTES = 65536

_REDACT_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|auth)\s*[=:]\s*['\"]?[^\s'\"]{6,}"), r"\1=***REDACTED***"),
    (re.compile(r"(?i)aws_secret_access_key\s*=\s*\S+"), "aws_secret_access_key=***REDACTED***"),
    (re.compile(r"(?i)aws_access_key_id\s*=\s*\S+"), "aws_access_key_id=***REDACTED***"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA***REDACTED***"),
    (re.compile(r"(?i)-----BEGIN[^-]+PRIVATE KEY-----[\s\S]*?-----END[^-]+PRIVATE KEY-----"), "***REDACTED_PRIVATE_KEY***"),
    (re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^\s]+"), r"\1://***REDACTED***"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"), "***REDACTED_GH_TOKEN***"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]+"), "***REDACTED_SLACK***"),
    (re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"), "Bearer ***REDACTED***"),
]


def redact(text: str) -> str:
    out = text
    for pat, repl in _REDACT_PATTERNS:
        out = pat.sub(repl, out)
    return out


def read_body(path: Optional[str]):
    if not path or not os.path.isfile(path):
        return "", 0, False
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_READ_BYTES + 1)
        original_len = os.path.getsize(path)
        truncated_read = len(raw) > MAX_READ_BYTES
        if truncated_read:
            raw = raw[:MAX_READ_BYTES]
        text = raw.decode("utf-8", errors="replace")
        return text, original_len, truncated_read or original_len > MAX_BODY_BYTES
    except Exception:
        return "", 0, False


def build_record(url, path, status_code, body_file=None, content_type=None, family=None):
    text, original_len, trunc = read_body(body_file)
    preview = redact(text)[:MAX_BODY_BYTES]
    body_truncated = trunc or (len(text) > MAX_BODY_BYTES)
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16] if text else ""
    return {
        "schema": "bugbountyci.info_disclosure_probe.v1",
        "url": url,
        "path": path,
        "status_code": int(status_code) if status_code is not None else None,
        "content_type": content_type,
        "family": family,
        "body_len": original_len,
        "body_truncated": body_truncated,
        "body_sha256_16": digest,
        "body": preview,
        "body_preview_redacted": True,
    }


def append_record(out_path: str, record: dict) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    key = (record.get("url"), record.get("path"), record.get("status_code"), record.get("body_sha256_16"))
    existing = set()
    if os.path.isfile(out_path):
        try:
            with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        r = json.loads(line)
                        existing.add((r.get("url"), r.get("path"), r.get("status_code"), r.get("body_sha256_16")))
                    except Exception:
                        continue
        except Exception:
            pass
    if key in existing:
        return
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--url", default="")
    p.add_argument("--path", default="/")
    p.add_argument("--status", type=int, default=0)
    p.add_argument("--body-file", default=None)
    p.add_argument("--content-type", default=None)
    p.add_argument("--family", default=None)
    p.add_argument("--init-only", action="store_true")
    args = p.parse_args(argv)
    if args.init_only:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        if not os.path.isfile(args.out):
            open(args.out, "w").close()
        return 0
    rec = build_record(args.url, args.path, args.status, args.body_file, args.content_type, args.family)
    append_record(args.out, rec)
    print(f"probe_recorded path={args.path} status={args.status} body_len={rec['body_len']} truncated={rec['body_truncated']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
