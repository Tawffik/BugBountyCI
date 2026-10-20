"""Offline tests for scripts/build_funnel_gate.py (RRP-3)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_funnel_gate import build, render_md  # noqa: E402


def test_starved_uro_pattern(tmp_path: Path) -> None:
    (tmp_path / "urls").mkdir()
    (tmp_path / "urls" / "wayback.txt").write_text("http://a.example/1\n" * 10)
    (tmp_path / "urls" / "all.txt").write_text("")  # empty merge
    (tmp_path / "live").mkdir()
    (tmp_path / "live" / "live.txt").write_text("https://a.example\n")
    report = build(tmp_path)
    assert report["verdict"] == "STARVED"
    assert any("wayback" in r.lower() or "uro" in r.lower() or "empty" in r.lower() for r in report["reasons"])
    md = render_md(report)
    assert "STARVED" in md


def test_dns_error(tmp_path: Path) -> None:
    (tmp_path / "subdomains").mkdir()
    (tmp_path / "subdomains" / "all_subs.txt").write_text("a.example\nb.example\n")
    (tmp_path / "subdomains" / "resolved.txt").write_text("")
    report = build(tmp_path)
    assert report["verdict"] == "ERROR"


def test_partial_thin_surface(tmp_path: Path) -> None:
    (tmp_path / "live").mkdir()
    (tmp_path / "urls").mkdir()
    # no live, no urls, no subs → PARTIAL thin
    report = build(tmp_path)
    assert report["verdict"] in {"PARTIAL", "FUNNEL_OK"}
