"""Unit tests for url_priority_filter — keep important paths without shrinking all.txt."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "url_priority_filter.py"


def test_priority_filter_keeps_sensitive_drops_pure_static(tmp_path: Path):
    urls = tmp_path / "urls"
    urls.mkdir()
    (urls / "all.txt").write_text(
        "\n".join(
            [
                "https://ex.com/.env",
                "https://ex.com/api/v1/users?id=1",
                "https://ex.com/static/logo.png",
                "https://ex.com/app.js.map",
                "https://ex.com/login",
            ]
        )
        + "\n"
    )
    r = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr
    high = (urls / "priority_high.txt").read_text()
    assert ".env" in high
    assert "api/v1" in high
    assert "app.js.map" in high
    assert "login" in high
    # inventory holds pure static when classified as such
    inv = (urls / "priority_inventory.txt").read_text()
    assert "logo.png" in inv or "logo.png" not in high
    stats = json.loads((tmp_path / "meta" / "url_filter_stats.json").read_text())
    assert stats["priority_high"] >= 4
    assert (urls / "all.txt").read_text().count("http") >= 5


def test_asn_priority_prefers_live_adjacent(tmp_path: Path):
    script = ROOT / "scripts" / "asn_priority_select.py"
    (tmp_path / "subdomains").mkdir()
    (tmp_path / "live").mkdir()
    ips = [f"10.0.0.{i}" for i in range(1, 5)] + [f"203.0.113.{i}" for i in range(1, 30)]
    # use public-ish test nets in script - private skipped; use 8.8.8.x and 1.2.3.x
    inv = [f"1.2.3.{i}" for i in range(1, 40)] + [f"9.9.9.{i}" for i in range(1, 20)]
    (tmp_path / "subdomains" / "asn_ips.txt").write_text("\n".join(inv) + "\n")
    (tmp_path / "live" / "live.txt").write_text("https://1.2.3.7/\n")
    r = subprocess.run(
        [sys.executable, str(script), "--results-dir", str(tmp_path), "--cap", "8"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr
    lines = (tmp_path / "subdomains" / "asn_ips_priority.txt").read_text().splitlines()
    assert lines[0] == "1.2.3.7"
    assert all(x.startswith("1.2.3.") for x in lines[:5])
    stats = json.loads((tmp_path / "meta" / "asn_priority_stats.json").read_text())
    assert stats["promoted"] == 8
