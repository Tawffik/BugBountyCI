"""Shared authorized-scope helpers for Zero Track.

Single rule for host/URL membership relative to an authorized apex domain.
Used by historical pivot, parameter intelligence consumers, and tests.
"""
from __future__ import annotations

import json
import os
from typing import Optional
from urllib.parse import urlparse


def normalize_domain(d: str | None) -> str:
    if not d:
        return ""
    return d.lower().strip().strip(".").lstrip(".")


def host_of(url_or_host: str) -> str:
    s = (url_or_host or "").strip()
    if not s:
        return ""
    if "://" not in s and "/" not in s and " " not in s:
        return normalize_domain(s)
    try:
        return normalize_domain(urlparse(s).hostname or "")
    except Exception:
        return ""


def in_scope_host(host: str, target_domain: str | None) -> bool:
    """True if host is the apex or a subdomain of target_domain.

    Rejects example.com.evil.com style suffix tricks.
    Empty target_domain → True (unscoped mode; callers should prefer scoped).
    """
    td = normalize_domain(target_domain)
    if not td:
        return True
    h = normalize_domain(host)
    if not h:
        return False
    return h == td or h.endswith("." + td)


def in_scope_url(url: str, target_domain: str | None) -> bool:
    """Relative paths (/...) are in scope; absolute URLs need host match."""
    u = (url or "").strip()
    if not u:
        return False
    if u.startswith("/") and not u.startswith("//"):
        return True
    return in_scope_host(host_of(u), target_domain)


def resolve_target_domain(
    results_dir: str | None = None,
    *,
    explicit: str | None = None,
    env: dict | None = None,
) -> Optional[str]:
    """Resolution order: explicit → TARGET env → target_profile.json → target.txt."""
    if explicit and explicit.strip():
        return normalize_domain(explicit)
    env = env if env is not None else os.environ
    t = (env.get("TARGET") or "").strip()
    if t:
        return normalize_domain(t)
    if results_dir:
        profile = os.path.join(results_dir, "meta", "target_profile.json")
        if os.path.isfile(profile):
            try:
                data = json.load(open(profile, encoding="utf-8"))
                for key in ("target", "domain", "authorized_domain"):
                    v = data.get(key)
                    if isinstance(v, str) and v.strip():
                        return normalize_domain(v)
            except Exception:
                pass
        for rel in ("target.txt", "meta/target.txt"):
            p = os.path.join(results_dir, rel)
            if os.path.isfile(p):
                try:
                    line = open(p, encoding="utf-8", errors="replace").readline().strip()
                    if line:
                        return normalize_domain(line.split()[0])
                except Exception:
                    pass
    return None
