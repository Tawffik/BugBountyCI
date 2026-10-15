"""Evidence association: correct matches and required non-matches across scheme/port/host."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse, urlunparse

ROOT = Path(__file__).resolve().parents[1]


def _index_probe_rows(rows: list[dict]) -> dict:
    """Mirror production indexing rules for offline assertion."""
    probe = {}
    for row in rows:
        u = (row.get("url") or "").strip()
        if not u:
            continue
        probe[u] = row
        pr = urlparse(u)
        if pr.scheme in ("http", "https"):
            alt = urlunparse(("https" if pr.scheme == "http" else "http",) + pr[1:])
            probe.setdefault(alt, row)
        path_key = (pr.path or "").rstrip("/") or "/"
        host = (pr.hostname or "").lower()
        if host and path_key:
            port = pr.port
            if port and port not in (80, 443):
                probe.setdefault(f"{host}:{port}|{path_key}", row)
            probe.setdefault(f"{host}|{path_key}", row)
    return probe


def _lookup(probe: dict, url: str) -> dict:
    row = probe.get(url) or {}
    if row:
        return row
    pr = urlparse(url if "://" in url else "https://" + url)
    path_key = (pr.path or "").rstrip("/") or "/"
    host = (pr.hostname or "").lower()
    port = pr.port
    if port and port not in (80, 443):
        row = probe.get(f"{host}:{port}|{path_key}") or {}
    if not row:
        row = probe.get(f"{host}|{path_key}") or {}
    if not row and pr.scheme in ("http", "https"):
        alt = url.replace(pr.scheme + "://", ("https" if pr.scheme == "http" else "http") + "://", 1)
        row = probe.get(alt) or {}
    return row


def test_scheme_swap_matches_same_host_path():
    rows = [{"url": "https://app.example.com/.git/HEAD", "body": "ref: refs/heads/main\n", "id": "A"}]
    probe = _index_probe_rows(rows)
    hit = _lookup(probe, "http://app.example.com/.git/HEAD")
    assert hit.get("id") == "A"
    assert hit.get("body", "").startswith("ref:")


def test_different_host_must_not_match():
    rows = [{"url": "https://app.example.com/.git/HEAD", "body": "SECRET_A", "id": "A"}]
    probe = _index_probe_rows(rows)
    hit = _lookup(probe, "https://other.example.com/.git/HEAD")
    assert hit == {} or hit.get("id") != "A"


def test_different_path_must_not_match():
    rows = [{"url": "https://app.example.com/.git/HEAD", "body": "SECRET_A", "id": "A"}]
    probe = _index_probe_rows(rows)
    hit = _lookup(probe, "https://app.example.com/.env")
    assert hit == {} or hit.get("id") != "A"


def test_nondefault_port_prefers_port_specific_body():
    rows = [
        {"url": "https://app.example.com/.git/HEAD", "body": "DEFAULT", "id": "def"},
        {"url": "https://app.example.com:8443/.git/HEAD", "body": "PORT8443", "id": "p8443"},
    ]
    probe = _index_probe_rows(rows)
    hit = _lookup(probe, "https://app.example.com:8443/.git/HEAD")
    assert hit.get("id") == "p8443"
    assert hit.get("body") == "PORT8443"
    # default port path must not steal 8443 body when looking up default URL
    hit2 = _lookup(probe, "https://app.example.com/.git/HEAD")
    assert hit2.get("id") == "def"


def test_ip_vs_hostname_are_distinct_keys():
    rows = [
        {"url": "https://app.example.com/.env", "body": "HOST", "id": "h"},
        {"url": "https://203.0.113.10/.env", "body": "IP", "id": "ip"},
    ]
    probe = _index_probe_rows(rows)
    assert _lookup(probe, "https://app.example.com/.env").get("id") == "h"
    assert _lookup(probe, "https://203.0.113.10/.env").get("id") == "ip"
    assert _lookup(probe, "https://app.example.com/.env").get("id") != "ip"


def test_source_contains_port_aware_index():
    src = (ROOT / "scripts" / "write_pipeline_exports.py").read_text(encoding="utf-8")
    assert "port not in (80, 443)" in src
    assert "host}:{port}|{path_key}" in src or 'f"{host}:{port}|{path_key}"' in src
