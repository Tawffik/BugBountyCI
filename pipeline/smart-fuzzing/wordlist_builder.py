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
# Real bug found reviewing a live run's actual target_wordlist.txt: Wolf
# contributed 220/300 (73%) of the final wordlist while vocabulary.json
# (this target's OWN evidence — words the application itself exposes)
# contributed only 5/2000 available words (0.25%) — the file's own
# "Signal Quality: evidence from the target beats a generic list"
# philosophy, inverted in practice. Root cause: wolf_selector.py's
# output (wolf_selected.txt) had ~4000 entries with no cap applied
# before being added to the candidate set, AND rank() put "not in
# wolf_lines" ahead of vocabulary words in sort priority — Wolf
# (generic) was outranking vocabulary.json (target-specific evidence),
# backwards from every other engine in this project. Every source now
# gets an explicit reserved share of the total cap, and the priority
# order is structural (this target's own grammar) > vocabulary (this
# target's own evidence) > Wolf (generic, supplementary only) - so no
# single source can crowd out the other two regardless of how many
# candidates it happens to produce.
STRUCTURAL_SHARE = {"light": 30, "normal": 80, "aggressive": 200}
VOCAB_SHARE = {"light": 40, "normal": 120, "aggressive": 350}
WOLF_SHARE = {"light": 30, "normal": 100, "aggressive": 250}

def _load_previous_strategy_outcome():
    """Compact historical note from Diff Mode snapshot if present.
    Never invents outcomes. Missing file = no adaptation.
    """
    candidates = [
        os.path.join(".previous_snapshot", "strategy_outcome.json"),
        os.path.join("..", ".previous_snapshot", "strategy_outcome.json"),
    ]
    for path in candidates:
        path = os.path.normpath(path)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", errors="ignore") as f:
                data = json.load(f)
            if isinstance(data, dict) and data.get("schema", "").startswith("bugbountyci.strategy_outcome"):
                return data
        except (OSError, json.JSONDecodeError, TypeError):
            continue
    return None



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

    # Base word candidates, ranked by evidence strength (more sources first),
    # capped to this run's vocabulary share BEFORE mixing with the other
    # sources — this is the set that was getting crowded out entirely.
    vocab_cap = VOCAB_SHARE.get(args.mode, VOCAB_SHARE["normal"])
    ranked_words = sorted(words, key=lambda w: vocab[w]["count"], reverse=True)
    vocab_candidates = []
    for w in ranked_words:
        for cand in (w, w + "s", *(f"{w}/{verb}" for verb in verbs_present if verb != w)):
            vocab_candidates.append(cand)
            if len(vocab_candidates) >= vocab_cap:
                break
        if len(vocab_candidates) >= vocab_cap:
            break
    vocab_candidates = vocab_candidates[:vocab_cap]

    prev_outcome = _load_previous_strategy_outcome()
    structural_cap = STRUCTURAL_SHARE.get(args.mode, STRUCTURAL_SHARE["normal"])
    # V3 adaptive: prior WAF-dominated run → shrink generic Wolf share, keep structural/vocab
    if prev_outcome and (prev_outcome.get("waf_rate") or 0) >= 0.5:
        wolf_cap_override = max(10, WOLF_SHARE.get(args.mode, 100) // 3)
    else:
        wolf_cap_override = None
    structural_paths = _load_predicted_fuzz_paths(out_dir)[:structural_cap]

    wolf_cap = wolf_cap_override if wolf_cap_override is not None else WOLF_SHARE.get(args.mode, WOLF_SHARE["normal"])
    wolf_candidates = wolf_lines[:wolf_cap]

    candidates = set(wolf_candidates) | set(vocab_candidates) | set(structural_paths)

    cap = MODE_CAPS.get(args.mode, MODE_CAPS["normal"])
    # structural (this target's own grammar) > vocabulary (this
    # target's own evidence) > Wolf (generic, supplementary) — see the
    # module-level comment for the real bug this ordering fixes.
    def rank(c):
        return (c not in structural_paths, c not in vocab_candidates, c not in wolf_candidates, c)

    final = list(dict.fromkeys(sorted(candidates, key=rank)))
    final = final[:cap]

    with open(out_path, "w") as f:
        for line in final:
            f.write(line + "\n")

    print(f"✅ target_wordlist.txt written ({len(final)} candidates, capped at {cap}, "
          f"mode={args.mode}) — sources: structural={len(structural_paths)}, "
          f"vocabulary={len(vocab_candidates)}, wolf={len(wolf_candidates)} "
          f"(wolf_selected.txt had {len(wolf_lines)} available, capped to {wolf_cap}) "
          f"-> {out_path}")


if __name__ == "__main__":
    main()

