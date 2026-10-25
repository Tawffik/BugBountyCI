#!/usr/bin/env python3
"""Shared scope helpers."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.scope import in_scope_host, in_scope_url, normalize_domain, resolve_target_domain


def test_host_scope_basic():
    assert in_scope_host("example.com", "example.com")
    assert in_scope_host("api.example.com", "example.com")
    assert not in_scope_host("evil.com", "example.com")
    assert not in_scope_host("example.com.evil.com", "example.com")
    assert in_scope_host("Example.COM.", "example.com")


def test_url_scope():
    assert in_scope_url("https://api.example.com/v1", "example.com")
    assert in_scope_url("/relative", "example.com")
    assert not in_scope_url("https://other.com/x", "example.com")


def test_resolve_from_profile(tmp_path):
    meta = tmp_path / "meta"
    meta.mkdir()
    (meta / "target_profile.json").write_text('{"target": "acme.test"}\n')
    assert resolve_target_domain(str(tmp_path)) == "acme.test"


def test_unscoped_allows_all():
    assert in_scope_host("anything.com", None)
    assert in_scope_host("anything.com", "")


if __name__ == "__main__":
    test_host_scope_basic()
    test_url_scope()
    import tempfile
    from pathlib import Path as P
    with tempfile.TemporaryDirectory() as d:
        test_resolve_from_profile(P(d))
    test_unscoped_allows_all()
    print("ok")
