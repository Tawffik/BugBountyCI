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
import re

MODE_CAPS = {"light": 120, "normal": 450, "aggressive": 900}
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
STRUCTURAL_SHARE = {"light": 30, "normal": 100, "aggressive": 220}
VOCAB_SHARE = {"light": 50, "normal": 180, "aggressive": 380}
WOLF_SHARE = {"light": 35, "normal": 120, "aggressive": 280}



def _load_passive_sensitive_path_seeds(out_dir):
    """Same-run Tips seeds from passive URL harvest (no live probe required)."""
    from urllib.parse import urlparse
    rd = os.path.dirname(out_dir.rstrip("/"))
    seeds = []
    seen = set()
    sens = re.compile(
        r"(admin|api|backup|\.env|swagger|openapi|debug|internal|staging|graphql|actuator)",
        re.I,
    )
    for rel in ("urls/priority_high.txt", "urls/sensitive_files.txt", "urls/juicy.txt", "urls/waymore.txt", "urls/gau.txt", "urls/wayback.txt", "urls/all.txt"):
        path = os.path.join(rd, rel)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i > 20000:
                        break
                    u = line.strip()
                    if not u or not sens.search(u):
                        continue
                    try:
                        path_part = (urlparse(u).path or "").strip("/")
                    except Exception:
                        continue
                    if not path_part or len(path_part) > 100 or path_part in seen:
                        continue
                    # single segment or short path
                    if path_part.count("/") > 3:
                        continue
                    seen.add(path_part)
                    seeds.append(path_part)
                    if len(seeds) >= 50:
                        return seeds
        except OSError:
            continue
    return seeds

def _load_archive_sensitive_paths(out_dir):
    """Tips archive→live leads: path component only, LEAD paths as structural hints."""
    rd = os.path.dirname(out_dir.rstrip("/"))
    path = os.path.join(rd, "info_disclosure", "archive_sensitive_probes.jsonl")
    if not os.path.isfile(path):
        # out_dir is .../smart-fuzzing; parent is results
        path = os.path.join(os.path.dirname(out_dir), "info_disclosure", "archive_sensitive_probes.jsonl")
    out = []
    if not os.path.isfile(path):
        return out
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(row.get("disposition") or "") not in ("CONTENT_LEAD", "AUTH_OR_FORBIDDEN"):
                    continue
                url = str(row.get("url") or "")
                if "://" in url:
                    path_part = "/" + url.split("://", 1)[1].split("/", 1)[-1] if "/" in url.split("://", 1)[1] else ""
                    # better: from urllib
                    from urllib.parse import urlparse
                    path_part = urlparse(url).path or ""
                else:
                    path_part = url
                path_part = path_part.strip("/")
                if path_part and len(path_part) < 120:
                    out.append(path_part)
    except OSError:
        return out
    return out[:40]


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
        if not fp:
            continue
        clean = _sanitize_fuzz_path_candidate(fp)
        if clean:
            fuzz_paths.append(clean)
    return fuzz_paths




def _sanitize_fuzz_path_candidate(raw: str) -> str | None:
    """Normalize a path-like evidence line into an ffuf-safe relative path.

    Live defect (run #165 superdrug): linkfinder lines such as
    ``[02dcea....js] /about-us`` were loaded verbatim into target_wordlist,
    producing non-fetchable ffuf entries and polluting the structural tier.
    """
    import re
    from urllib.parse import urlparse

    line = (raw or "").strip()
    if not line or line.startswith("#"):
        return None
    # Drop bracket tags: [200], [hash.js], etc.
    line = re.sub(r"\[[^\]]*\]", " ", line).strip()
    if "://" in line:
        for tok in line.split():
            if "://" in tok:
                line = tok
                break
        try:
            path_only = urlparse(line).path or ""
        except Exception:
            return None
    else:
        # Prefer the last slash-bearing token (handles "tag /path")
        parts = line.split()
        path_only = parts[-1] if parts else line
    path_only = path_only.strip()
    if not path_only or path_only == "/":
        return None
    cand = path_only.lstrip("/")
    if not cand or cand.startswith("{") or " " in cand:
        return None
    # Reject static asset / hash-looking single segments
    segs = [s for s in cand.split("/") if s]
    if not segs:
        return None
    ASSET_EXT = (
        ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".woff", ".woff2", ".ttf", ".ico", ".html", ".htm", ".webp", ".mp4",
    )
    if any(s.lower().endswith(ASSET_EXT) for s in segs):
        return None
    # Marketing/cache path noise (run #165 superdrug wordlist): ss4314.05.html style
    if any(re.search(r"\d+\.\d+", s) for s in segs):
        return None
    if len(segs) == 1 and re.fullmatch(r"[0-9a-f]{16,}", segs[0], re.I):
        return None
    if len(cand) > 180:
        return None
    return cand


def _load_path_file_candidates(path: str, limit: int = 200) -> list[str]:
    """Load path-like lines from an evidence file for ffuf (strip scheme/host)."""
    if not path or not os.path.isfile(path):
        return []
    out: list[str] = []
    seen: set[str] = set()
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                cand = _sanitize_fuzz_path_candidate(line)
                if not cand or cand in seen:
                    continue
                seen.add(cand)
                out.append(cand)
                if len(out) >= limit:
                    break
    except OSError:
        return []
    return out


def _load_linkfinder_fuzz_paths(out_dir) -> list[str]:
    path = os.path.normpath(os.path.join(out_dir, "..", "js_deep", "linkfinder_endpoints.txt"))
    return _load_path_file_candidates(path, limit=150)


def _load_admin_fuzz_paths(out_dir) -> list[str]:
    path = os.path.normpath(os.path.join(out_dir, "..", "js", "admin.txt"))
    return _load_path_file_candidates(path, limit=40)


def _load_api_urls_fuzz_paths(out_dir) -> list[str]:
    path = os.path.normpath(os.path.join(out_dir, "..", "urls", "api_urls.txt"))
    return _load_path_file_candidates(path, limit=100)

def _load_swagger_fuzz_paths(out_dir):
    """OpenAPI path keys extracted in API Discovery (js/swagger_paths.txt)."""
    path = os.path.normpath(os.path.join(out_dir, "..", "js", "swagger_paths.txt"))
    if not os.path.isfile(path):
        return []
    out = []
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("/"):
                    line = line.lstrip("/")
                # skip pure parameter templates noise
                if not line or line.startswith("{"):
                    continue
                out.append(line)
    except OSError:
        return []
    return out


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
    for ap in _load_passive_sensitive_path_seeds(out_dir) + _load_archive_sensitive_paths(out_dir):
        if ap not in structural_paths:
            structural_paths.append(ap)
        if len(structural_paths) >= structural_cap:
            break
    # OpenAPI paths are target-specific evidence — same tier as structural
    for sp in (
        _load_swagger_fuzz_paths(out_dir)
        + _load_linkfinder_fuzz_paths(out_dir)
        + _load_admin_fuzz_paths(out_dir)
        + _load_api_urls_fuzz_paths(out_dir)
    ):
        if sp not in structural_paths:
            structural_paths.append(sp)
        if len(structural_paths) >= structural_cap:
            break

    wolf_cap = wolf_cap_override if wolf_cap_override is not None else WOLF_SHARE.get(args.mode, WOLF_SHARE["normal"])
    # When structural predictions are absent, generic Wolf must not dominate
    # the target-specific wordlist (same failure class as the 73% Wolf bug).
    if not structural_paths:
        wolf_cap = min(wolf_cap, max(15, VOCAB_SHARE.get(args.mode, 120) // 3))
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

