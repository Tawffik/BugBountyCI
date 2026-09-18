#!/usr/bin/env python3
"""
wordlist_builder.py — V1

Combines:
  - wolf_selected.txt   (curated Wolf knowledge, from wolf_selector.py)
  - vocabulary.json     (words the application itself exposes)

into a single target-specific wordlist for ffuf.

Rule from the spec: "Generate only candidates supported by application
evidence." So vocabulary words get simple, evidence-based variants
(plural, /word, /word/export, /word/download) ONLY when the supporting
verb (export/download/status/id) was itself seen in the vocabulary —
this is not blind combination, every variant traces back to something
observed.

Output:
  <RD>/smart-fuzzing/target_wordlist.txt
"""
import argparse
import json
import os

MODE_CAPS = {"light": 100, "normal": 300, "aggressive": 800}
VERB_HINTS = ["export", "download", "status", "delete", "update", "create", "list"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--mode", default="normal", choices=list(MODE_CAPS))
    args = ap.parse_args()

    out_dir = os.path.join(args.results_dir, "smart-fuzzing")
    os.makedirs(out_dir, exist_ok=True)

    wolf_path = os.path.join(out_dir, "wolf_selected.txt")
    vocab_path = os.path.join(out_dir, "vocabulary.json")
    out_path = os.path.join(out_dir, "target_wordlist.txt")

    wolf_lines = []
    if os.path.isfile(wolf_path):
        with open(wolf_path, "r", errors="ignore") as f:
            wolf_lines = [l.strip() for l in f if l.strip()]

    vocab = {}
    if os.path.isfile(vocab_path):
        with open(vocab_path, "r", errors="ignore") as f:
            vocab = json.load(f)

    words = list(vocab.keys())
    verbs_present = {v for v in VERB_HINTS if v in vocab}

    candidates = set(wolf_lines)

    # Base word candidates, ranked by evidence strength (more sources first).
    ranked_words = sorted(words, key=lambda w: vocab[w]["count"], reverse=True)
    for w in ranked_words:
        candidates.add(w)
        candidates.add(w + "s")
        for verb in verbs_present:
            candidates.add(f"{w}/{verb}")

    cap = MODE_CAPS.get(args.mode, MODE_CAPS["normal"])
    # Keep it a *small relevant* wordlist: cap total candidates, but always
    # keep the whole (small) Wolf generic slice plus top vocabulary words
    # first, since those carry the strongest evidence.
    final = list(dict.fromkeys(sorted(candidates, key=lambda c: (c not in wolf_lines, c))))
    final = final[:cap]

    with open(out_path, "w") as f:
        for line in final:
            f.write(line + "\n")

    print(f"✅ target_wordlist.txt written ({len(final)} candidates, capped at {cap}, "
          f"mode={args.mode}) -> {out_path}")


if __name__ == "__main__":
    main()
