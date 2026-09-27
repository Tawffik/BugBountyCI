#!/usr/bin/env python3
"""
wordlist_builder.py — V1

Combines:
  - wolf_selected.txt      (curated Wolf knowledge, from wolf_selector.py)
  - vocabulary.json        (words the application itself exposes)
  - predicted_paths.json   (this target's OWN structural grammar,
                            learned from its real discovered URLs by
                            pipeline/detection/pattern_predictor.py —
                            e.g. this target uses "delivery" as an
                            action on one resource and has an
                            id-bearing "invoices" resource that never
                            showed that action, so predict
                            invoices/<real-id>/delivery)

into a single target-specific wordlist for ffuf. Nothing here is
target-specific by name — every target gets its own wolf_selected.txt,
vocabulary.json and predicted_paths.json from the SAME run, so this
script (and the grammar it draws from) works unmodified on whatever
TARGET the workflow was run against.

Rule from the spec: "Generate only candidates supported by application
evidence." So vocabulary words get simple, evidence-based variants
(plural, /word, /word/export, /word/download) ONLY when the supporting
verb (export/download/status/id) was itself seen in the vocabulary —
this is not blind combination, every variant traces back to something
observed. Structural predictions carry their own evidence trail (see
pattern_predictor.py) and are added as ranked-first, since a predicted
full path is a stronger, more specific lead than a bare word guess.

Output:
  <RD>/smart-fuzzing/target_wordlist.txt
"""
import argparse
import json
import os

MODE_CAPS = {"light": 100, "normal": 300, "aggressive": 800}
VERB_HINTS = ["export", "download", "status", "delete", "update", "create", "list"]
# Reserve part of the cap for structural predictions specifically, so a
# target with a rich grammar doesn't get crowded out entirely by plain
# vocabulary words — but never let predictions alone blow past the cap.
STRUCTURAL_SHARE = {"light": 30, "normal": 80, "aggressive": 200}


def _load_predicted_fuzz_paths(out_dir):
    """Read predicted_paths.json (if pattern_predictor.py ran for this
    target) and return the fuzzable, real-id-substituted path strings
    — never the bare "{id}" placeholder form, ffuf can't test that."""
    path = os.path.join(out_dir, "..", "detection", "predicted_paths.json")
    path = os.path.normpath(path)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", errors="ignore") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    fuzz_paths = []
    for entry in data:
        fp = (entry.get("evidence") or {}).get("fuzz_path")
        if fp:
            fuzz_paths.append(fp)
    return fuzz_paths


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
            if verb == w:
                continue  # don't pair a word with itself ("export/export")
            candidates.add(f"{w}/{verb}")

    structural_cap = STRUCTURAL_SHARE.get(args.mode, STRUCTURAL_SHARE["normal"])
    structural_paths = _load_predicted_fuzz_paths(out_dir)[:structural_cap]
    candidates.update(structural_paths)

    cap = MODE_CAPS.get(args.mode, MODE_CAPS["normal"])
    # Keep it a *small relevant* wordlist: cap total candidates, but rank
    # structural predictions first (this target's own grammar — the
    # strongest evidence), then the (small) Wolf generic slice, then
    # plain vocabulary words/verb-pairs last.
    def rank(c):
        return (c not in structural_paths, c not in wolf_lines, c)

    final = list(dict.fromkeys(sorted(candidates, key=rank)))
    final = final[:cap]

    with open(out_path, "w") as f:
        for line in final:
            f.write(line + "\n")

    print(f"✅ target_wordlist.txt written ({len(final)} candidates, capped at {cap}, "
          f"mode={args.mode}, {len(structural_paths)} from this target's own "
          f"structural grammar) -> {out_path}")


if __name__ == "__main__":
    main()

