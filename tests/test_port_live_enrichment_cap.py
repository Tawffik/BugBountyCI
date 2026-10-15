"""Regression: pure-IP port enrichment must be capped; hostnames unlimited.

Evidence: run #162 capital.com produced ports.txt with 28630 pure-IP lines;
unbounded merge into live.txt yielded 28734 IP URLs and broke tech/scan_order.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def split_port_urls(port_lines: list[str], ip_cap: int = 200) -> tuple[list[str], list[str], list[str]]:
    """Return (host_urls, ip_urls_all, ip_urls_promoted)."""
    host_urls: list[str] = []
    ip_urls: list[str] = []
    for hp in port_lines:
        hp = (hp or "").strip()
        if not hp or ":" not in hp:
            continue
        host, _, port = hp.partition(":")
        if not host or not port:
            continue
        if port in ("443", "8443", "9443"):
            candidates = [f"https://{host}"]
            if port != "443":
                candidates.append(f"https://{host}:{port}")
        elif port == "80":
            candidates = [f"http://{host}", f"https://{host}"]
        else:
            candidates = [f"http://{host}:{port}", f"https://{host}:{port}"]
        bucket = ip_urls if IP_RE.fullmatch(host) else host_urls
        for c in candidates:
            if c not in bucket:
                bucket.append(c)
    promoted = ip_urls[:ip_cap]
    return host_urls, ip_urls, promoted


def test_hostname_ports_always_promoted():
    host_u, ip_u, prom = split_port_urls(
        ["api.example.com:443", "admin.example.com:8080", "10.0.0.1:443"],
        ip_cap=2,
    )
    assert "https://api.example.com" in host_u
    assert "http://admin.example.com:8080" in host_u
    assert any("10.0.0.1" in u for u in ip_u)
    assert len(prom) <= 2


def test_pure_ip_flood_is_capped():
    lines = [f"1.2.3.{i % 250}:443" for i in range(5000)]
    host_u, ip_u, prom = split_port_urls(lines, ip_cap=200)
    assert host_u == []
    assert len(ip_u) >= 200
    assert len(prom) == 200


def test_empty_ports():
    assert split_port_urls([]) == ([], [], [])


def test_live_txt_merge_size_bound():
    """Simulated merge must keep live far below unbounded ASN flood."""
    seed = [f"https://sub{i}.example.com" for i in range(50)]
    ports = [f"9.9.9.{i % 200}:443" for i in range(20000)]
    host_u, ip_u, prom = split_port_urls(ports, ip_cap=200)
    merged = sorted(set(seed + host_u + prom))
    assert len(merged) <= 50 + 200
    assert len(merged) < 1000  # vs 28k regression
