#!/usr/bin/env python3
"""
baseline.py — V1

Before trusting any fuzz hit, learn how the target responds to something
that definitely does NOT exist. This is the SPA-fallback problem
(intigriti.com/researchers/blog/hacking-tools/web-fuzzing-for-hackers):
many apps return 200 + identical content for every path, which would
otherwise make every single fuzz candidate look like a "hit".

For each host, requests two random nonexistent paths and records status,
content length, content-type, and a coarse content fingerprint
(md5 of the body with digits stripped, so timestamps/nonces/csrf tokens
don't defeat the fingerprint).

Output:
  <RD>/smart-fuzzing/baseline.json
    { "https://host": {"status": 200, "length": 8421,
                        "content_type": "text/html", "fingerprint": "..."} }
"""
import argparse
import hashlib
import json
import os
import random
import re
import string
import subprocess


def random_token(n=14):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def fingerprint(body):
    normalized = re.sub(r"\d+", "", body or "")
    return hashlib.md5(normalized.encode("utf-8", "ignore")).hexdigest()


def probe(host, user_agent, use_tor, timeout=10):
    """One GET to host/<random-nonexistent-path>. Uses curl (already a
    hard dependency everywhere else in this pipeline) instead of adding a
    new HTTP library dependency."""
    path = random_token()
    url = host.rstrip("/") + "/" + path
    cmd = []
    if use_tor:
        cmd = ["proxychains4", "-q"]
    cmd += [
        "curl", "-sk", "--max-time", str(timeout),
        "-H", f"User-Agent: {user_agent}",
        "-w", "\n%{http_code}\n%{content_type}",
        url,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        out = result.stdout
    except Exception:
        return None

    parts = out.rsplit("\n", 2)
    if len(parts) != 3:
        return None
    body, status, content_type = parts
    status = status.strip()
    if not status.isdigit():
        return None
    return {
        "status": int(status),
        "length": len(body),
        "content_type": content_type.strip() or "unknown",
        "fingerprint": fingerprint(body),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--hosts-file", required=True, help="one host (with scheme) per line")
    ap.add_argument("--user-agent", default="Mozilla/5.0")
    ap.add_argument("--use-tor", action="store_true")
    ap.add_argument("--max-hosts", type=int, default=20,
                     help="cap how many hosts get baselined, largest scans stay bounded")
    args = ap.parse_args()

    out_dir = os.path.join(args.results_dir, "smart-fuzzing")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "baseline.json")

    hosts = []
    if os.path.isfile(args.hosts_file):
        with open(args.hosts_file, "r", errors="ignore") as f:
            hosts = [l.strip() for l in f if l.strip()][: args.max_hosts]

    baselines = {}
    for host in hosts:
        # Two probes: if they disagree wildly, the host isn't giving a
        # stable fallback and V1 should just skip diffing it rather than
        # risk a baseline built from a fluke.
        p1 = probe(host, args.user_agent, args.use_tor)
        p2 = probe(host, args.user_agent, args.use_tor)
        if not p1 or not p2:
            continue
        if p1["fingerprint"] != p2["fingerprint"]:
            baselines[host] = {**p1, "stable": False}
        else:
            baselines[host] = {**p1, "stable": True}

    with open(out_path, "w") as f:
        json.dump(baselines, f, indent=2)

    stable = sum(1 for b in baselines.values() if b.get("stable"))
    print(f"✅ baseline.json written ({len(baselines)} host(s), {stable} stable) -> {out_path}")


if __name__ == "__main__":
    main()
