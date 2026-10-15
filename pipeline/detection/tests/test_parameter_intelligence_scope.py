"""parameter_intelligence must not emit third-party endpoints as candidates."""
from __future__ import annotations

import json
from pathlib import Path

from pipeline.detection.parameter_intelligence import build, _endpoint_in_scope


def test_endpoint_in_scope_subdomain():
    assert _endpoint_in_scope("https://api.example.com/v1", "example.com")
    assert _endpoint_in_scope("https://example.com/x", "example.com")
    assert not _endpoint_in_scope("https://evil.com/x", "example.com")
    assert not _endpoint_in_scope("https://example.com.evil.com/x", "example.com")
    assert _endpoint_in_scope("/relative/path", "example.com")


def test_build_drops_third_party_urls(tmp_path: Path):
    (tmp_path / "urls").mkdir()
    (tmp_path / "urls" / "gf_categorized.txt").write_text(
        "https://example.com/app?redirect=1\n"
        "https://thirdparty.example.org/help?url=1\n"
        "https://api.example.com/v1?next=/\n"
    )
    data = build(str(tmp_path), target_domain="example.com")
    eps = [e["endpoint"] for e in data["endpoints"]]
    assert any("example.com" in e for e in eps)
    assert not any("thirdparty.example.org" in e for e in eps)
    assert data.get("endpoints_dropped_out_of_scope", 0) >= 1


def test_build_without_target_keeps_all(tmp_path: Path):
    (tmp_path / "urls").mkdir()
    (tmp_path / "urls" / "gf_categorized.txt").write_text(
        "https://a.example/x?a=1\nhttps://b.other/y?b=1\n"
    )
    data = build(str(tmp_path), target_domain=None)
    assert data["endpoint_count"] >= 1
