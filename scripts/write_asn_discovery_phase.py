#!/usr/bin/env python3
"""Write meta/phases/asn_discovery.json — inventory success ≠ promotion volume."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    args = ap.parse_args()
    rd = Path(args.results_dir)
    def nlines(rel: str) -> int:
        p = rd / rel
        if not p.is_file():
            return 0
        return sum(1 for l in p.open(errors="ignore") if l.strip())

    cidrs = nlines("subdomains/asn_cidrs.txt")
    ips = nlines("subdomains/asn_ips.txt")
    src = ""
    sp = rd / "meta" / "asn_source.txt"
    if sp.is_file():
        src = sp.read_text(encoding="utf-8", errors="replace").strip()
    status = "ok" if (cidrs or ips) else "empty"
    phase = {
        "schema": "bugbountyci.phase.v1",
        "phase": "asn_discovery",
        "status": status,
        "detail": f"cidrs={cidrs} asn_ips={ips} source={src or 'none'}",
        "counts": {"asn_cidrs": cidrs, "asn_ips": ips},
        "note": (
            "Full ASN/CIDR inventory is retained here. Live host and port "
            "promotion are intentionally capped later (meta/resource_caps.json). "
            "Low live/port counts vs inventory are expected — not an asnmap failure."
        ),
    }
    out = rd / "meta" / "phases"
    out.mkdir(parents=True, exist_ok=True)
    (out / "asn_discovery.json").write_text(json.dumps(phase, indent=2) + "\n", encoding="utf-8")
    print(f"✅ asn_discovery phase status={status} cidrs={cidrs} ips={ips}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
