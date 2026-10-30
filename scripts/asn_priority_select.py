#!/usr/bin/env python3
"""Select which ASN inventory IPs promote to active port scan.

Full inventory stays in subdomains/asn_ips.txt. This writes
subdomains/asn_ips_priority.txt (up to --cap) preferring:
  1) IPs already seen on live surface
  2) IPs sharing /24 with live or resolved host dig results
  3) remaining inventory (stable order) to fill the cap

Does not expand naabu budget beyond --cap; changes *which* IPs matter.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
from pathlib import Path

IP_RE = re.compile(r"\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")


def _ips_from_file(path: Path) -> list[str]:
    if not path.is_file():
        return []
    out: list[str] = []
    seen: set[str] = set()
    text = path.read_text(errors="replace")
    for m in IP_RE.finditer(text):
        ip = m.group(0)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            continue
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _slash24(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--cap", type=int, default=300)
    args = ap.parse_args()
    rd = Path(args.results_dir)
    sub = rd / "subdomains"
    live = rd / "live"
    sub.mkdir(parents=True, exist_ok=True)

    inventory = _ips_from_file(sub / "asn_ips.txt")
    live_ips = set(_ips_from_file(live / "live.txt"))
    # resolved hostnames file may mix names and ips
    for extra in (sub / "resolved.txt", live / "hostname_targets.txt"):
        live_ips.update(_ips_from_file(extra))

    live_24 = {_slash24(ip) for ip in live_ips}

    tier1 = [ip for ip in inventory if ip in live_ips]
    tier2 = [ip for ip in inventory if ip not in live_ips and _slash24(ip) in live_24]
    tier3 = [ip for ip in inventory if ip not in live_ips and _slash24(ip) not in live_24]

    ordered: list[str] = []
    seen: set[str] = set()
    for bucket in (tier1, tier2, tier3):
        for ip in bucket:
            if ip not in seen:
                seen.add(ip)
                ordered.append(ip)

    cap = max(1, args.cap)
    promoted = ordered[:cap]
    out_path = sub / "asn_ips_priority.txt"
    out_path.write_text("\n".join(promoted) + ("\n" if promoted else ""))

    stats = {
        "schema": "bugbountyci.asn_priority_select.v1",
        "inventory": len(inventory),
        "tier1_live_overlap": len(tier1),
        "tier2_same_slash24": len(tier2),
        "tier3_rest": len(tier3),
        "cap": cap,
        "promoted": len(promoted),
        "note": "Full asn_ips.txt retained; promoted list prefers live-adjacent IPs.",
    }
    meta = rd / "meta"
    meta.mkdir(parents=True, exist_ok=True)
    (meta / "asn_priority_stats.json").write_text(json.dumps(stats, indent=2) + "\n")
    print(
        f"✅ asn_priority_select: inventory={len(inventory)} "
        f"promoted={len(promoted)}/{cap} "
        f"(t1={len(tier1)} t2={len(tier2)} t3={len(tier3)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
