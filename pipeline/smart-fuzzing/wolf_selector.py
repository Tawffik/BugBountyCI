#!/usr/bin/env python3
"""
wolf_selector.py — V1

Wolf (https://github.com/0xBugatti/wolf) is a knowledge source, not a
scanner: 2,500+ plain-text lists under DIRS/, HTTP/, DNS/, etc. This
script does NOT dump the whole thing on every target. It walks Wolf's
DIRS/ and HTTP/parameters/ trees and pulls only:
  1. generic content-discovery lists (admin, backups, APIs)
  2. technology-specific lists matching target_profile.json's
     "technologies" (e.g. WordPress -> any Wolf path containing
     "wordpress")
  3. a small parameter list from HTTP/parameters/

Everything else in Wolf (Credentials/, Exploits/, VULNS/, Ai/, Dork/) is
out of scope for V1 content discovery.

Output:
  <RD>/smart-fuzzing/wolf_selected.txt   (deduped, capped)
"""
import argparse
import json
import os

# Per-mode cap on total *lines* pulled from Wolf before dedup/merge with
# app vocabulary in wordlist_builder.py. Keeps this a "small relevant
# wordlist", not "all of Wolf".
MODE_CAPS = {"light": 1500, "normal": 4000, "aggressive": 10000}

GENERIC_DIR_HINTS = ["admin", "login", "panel", "backup", "api", "config"]


def find_files(root, name_hint=None):
    """Yield .txt file paths under root whose path (case-insensitive)
    contains name_hint, or all .txt files if name_hint is None."""
    if not os.path.isdir(root):
        return
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if not fn.lower().endswith(".txt"):
                continue
            full = os.path.join(dirpath, fn)
            if name_hint is None or name_hint.lower() in full.lower():
                yield full


def read_capped(path, remaining_budget):
    lines = []
    if remaining_budget <= 0:
        return lines
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                lines.append(line)
                if len(lines) >= remaining_budget:
                    break
    except OSError:
        pass
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wolf-dir", required=True, help="path to a local Wolf checkout")
    ap.add_argument("--target-profile", required=True, help="path to target_profile.json")
    ap.add_argument("--mode", default="normal", choices=list(MODE_CAPS))
    ap.add_argument("--results-dir", required=True)
    args = ap.parse_args()

    out_dir = os.path.join(args.results_dir, "smart-fuzzing")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "wolf_selected.txt")

    if not os.path.isdir(args.wolf_dir):
        print(f"⚠️ Wolf dir not found at {args.wolf_dir} — writing empty selection "
              f"(target-specific wordlist will fall back to app vocabulary only).")
        open(out_path, "w").close()
        return

    with open(args.target_profile, "r", errors="ignore") as f:
        profile = json.load(f)
    technologies = profile.get("technologies", [])
    api_present = profile.get("api_present", False)

    budget = MODE_CAPS.get(args.mode, MODE_CAPS["normal"])
    selected = set()
    picked_files = []

    dirs_root = os.path.join(args.wolf_dir, "DIRS")
    http_root = os.path.join(args.wolf_dir, "HTTP")

    # 1. Generic content-discovery lists (admin/login/backup/config), a
    #    small fixed slice regardless of technology — this is the closest
    #    V1 equivalent of the old common.txt, but curated.
    for hint in GENERIC_DIR_HINTS:
        for path in find_files(dirs_root, hint):
            if len(selected) >= budget:
                break
            lines = read_capped(path, budget - len(selected))
            if lines:
                selected.update(lines)
                picked_files.append(path)

    # 2. Technology-specific lists.
    for tech in technologies:
        tech_token = tech.split()[0].strip()  # "Next.js" -> "Next.js"; keep as-is, substring match handles it
        if len(tech_token) < 3:
            continue
        for path in find_files(dirs_root, tech_token):
            if len(selected) >= budget:
                break
            lines = read_capped(path, budget - len(selected))
            if lines:
                selected.update(lines)
                picked_files.append(path)

    # 3. A small parameter list, only if the target actually exposes an API —
    #    matches the doc's rule "select knowledge based on the target".
    if api_present:
        for path in find_files(os.path.join(http_root, "parameters")):
            if len(selected) >= budget:
                break
            lines = read_capped(path, min(500, budget - len(selected)))
            if lines:
                selected.update(lines)
                picked_files.append(path)
            break  # one parameter list is enough for V1

    with open(out_path, "w") as f:
        for line in sorted(selected):
            f.write(line + "\n")

    print(f"✅ wolf_selected.txt written ({len(selected)} lines from {len(picked_files)} "
          f"Wolf file(s), mode={args.mode}) -> {out_path}")


if __name__ == "__main__":
    main()
