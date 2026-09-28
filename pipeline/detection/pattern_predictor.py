#!/usr/bin/env python3
"""
pipeline/detection/pattern_predictor.py

This is the answer to a specific project gap: everything built so far
(wolf_selector, wordlist_builder's word+verb pairing, the fixed
PATH_MUTATIONS list in access_control_engine, the fixed param-name list
in open_redirect_engine) draws from *static* sources — a list from Wolf,
or a fixed set of mutations/param names applied identically to every
target. None of it learns the target's *own* URL grammar.

Arow's technique (Intigriti "custom wordlist" method this module is
modelled on): don't fuzz with someone else's wordlist — read the app's
*own* discovered paths, work out its structural conventions (resource
names, action/sub-resource names, where IDs sit), and predict new paths
that fit that grammar but weren't directly observed. A site that has
  /orders/{id}/delivery
  /profile/dependant/edit_profile/add_avatar
tells you more about what "/invoices/{id}/export" might look like on
THIS site than any generic wordlist does — IF "invoices" and "export"
are themselves words this site actually uses elsewhere.

Scope of this module: it is a pure function of already-collected recon
data (urls/all.txt + optionally vocabulary.json). It does not make any
network requests itself. It is deliberately engine-agnostic — it emits
PathPrediction objects with full evidence (which real path the shape
came from, which real path the substituted word came from), so ANY
consumer (smart-fuzzing's wordlist_builder, access_control_engine,
open_redirect_engine) can turn predictions into candidates in whatever
form that engine needs. See docs/V2_ROADMAP.md for the wiring order:
wordlist_builder first (this commit), access-control/open-redirect next
once this is validated against a real run — same "smallest step, prove
it, then extend" discipline as every other engine in this project.

Output when run standalone:
  <RD>/detection/predicted_paths.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlsplit

ID_PLACEHOLDER = "{id}"

# Same threshold family as vocabulary.py's looks_like_hash — kept as an
# independent local copy since pipeline/smart-fuzzing is not an
# importable package (hyphen in the dir name) and every module in this
# project is a standalone script invoked via CLI, not cross-imported.
HEX_HASH_RE = re.compile(r"^[0-9a-f]{8,}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
WORD_RE = re.compile(r"^[a-z][a-z_-]{1,29}$")

STATIC_ASSET_EXT = {
    "js", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "woff",
    "woff2", "ttf", "eot", "ico", "webp", "mp4", "webmanifest",
}

# Segments this common on a real site carry ~zero structural signal
# (they're framework/CDN plumbing, not application resources).
SEGMENT_STOPWORDS = {
    "static", "assets", "public", "dist", "build", "node_modules",
    "_next", "chunks", "img", "images", "fonts", "css", "js",
}

MAX_URLS_SCANNED = 20000
MAX_PREDICTIONS = 300  # safety cap — same philosophy as every other
                        # generator in this project (vocabulary.py's
                        # MAX_VOCAB_SIZE, wordlist_builder's MODE_CAPS):
                        # an unbounded generator has burned this project
                        # before (the 58,932-word vocabulary.json bug).


def _looks_like_id(segment: str) -> bool:
    """True if this path segment is a value (an ID), not a structural
    word — numeric, hex hash, UUID, or a bracket placeholder some
    crawlers already leave in (e.g. "[customer_order_id]")."""
    s = segment.strip()
    if not s:
        return True
    if s.startswith("[") and s.endswith("]"):
        return True
    if s.isdigit():
        return True
    if UUID_RE.match(s):
        return True
    if HEX_HASH_RE.match(s.lower()) and len(s) >= 8:
        return True
    digit_ratio = sum(c.isdigit() for c in s) / len(s)
    if digit_ratio > 0.4 and len(s) >= 6:
        return True
    return False


def _case_transitions(segment: str) -> int:
    """Count upper<->lower transitions in the ORIGINAL (pre-lowercase)
    segment. Real English path words, even camelCase ones like
    "userId"/"accountId", have at most 1-2 transitions. A random
    Base62-ish analytics-beacon token like "IgIbxOc" has many more
    relative to its length (I-g-I-b-x-O-c: 4 transitions in 7 chars)."""
    transitions = 0
    for a, b in zip(segment, segment[1:]):
        if a.isalpha() and b.isalpha() and a.isupper() != b.isupper():
            transitions += 1
    return transitions


def _looks_like_word(segment: str) -> bool:
    """True if this segment is a plausible structural word worth
    learning from — rejects junk that survives _looks_like_id (long
    random tokens, cache-busting strings, single letters).

    Real-data bug caught on superdrug.com, twice: analytics/tracking-
    pixel beacon URLs (e.g. ".../1GCOOA8_/Xr1uqbJ/.../OHUXAQ/...",
    later ".../zdNmBusA/9bQ8Fo7/IgIbxOc/...") have segments that are
    random Base62-ish tokens. The first fix only rejected pure
    ALL-CAPS segments ("OHUXAQ") — that missed mixed-case random
    tokens like "IgIbxOc", which is NOT all-uppercase and slipped
    straight through, polluting the learned action vocabulary badly
    enough to get paired with nearly every resource on the site
    ("/{resource}/{id}/igibxoc" for ~300 different resources in one
    real run). Real application path segments in this project's data
    are essentially always lower/kebab/snake case, or at most simple
    camelCase (1-2 transitions) — reject anything with 3+ case
    transitions as a random token, not a word, regardless of whether
    it happens to be all-caps, all-lowercase, or mixed."""
    if segment.isupper() and len(segment) >= 4:
        return False  # e.g. "OHUXAQ" — 0 case transitions, but still random
    if _case_transitions(segment) >= 3:
        return False
    s = segment.lower().strip()
    if not WORD_RE.match(s):
        return False
    if s in SEGMENT_STOPWORDS:
        return False
    ext = s.rsplit(".", 1)[-1] if "." in s else ""
    if ext in STATIC_ASSET_EXT:
        return False
    return True


def in_scope(url: str, target_domain: str | None) -> bool:
    """True if url's host is the target domain or a subdomain of it.

    Real-data bug caught on superdrug.com: urls/all.txt (wayback/gau
    output) contains third-party domains too (nhs.uk, sciencedirect.com,
    drugs.com, royalmail.com help-widget links, ...) — pages the target
    merely links to or cites, not the target's own application. Without
    this filter, the grammar gets polluted with another site's URL
    conventions (e.g. a Oracle/RightNow help-widget path like
    "/app/answers/detail/a_id/12556" from royalmail.com's help center)
    and produces predictions that look plausible but describe a domain
    we were never asked to test.
    """
    if not target_domain:
        return True  # no filter configured — caller's responsibility
    try:
        host = urlsplit(url).netloc.split(":")[0].lower()
    except ValueError:
        return False
    target_domain = target_domain.lower().lstrip(".")
    return host == target_domain or host.endswith("." + target_domain)


def _split_path(url: str) -> list[str] | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.path or parts.path == "/":
        return None
    # A trailing static-asset extension on the LAST segment means this
    # whole URL is an asset, not an application route — skip it
    # entirely rather than trying to learn structure from a JS chunk.
    last = parts.path.rsplit("/", 1)[-1]
    if "." in last:
        ext = last.rsplit(".", 1)[-1].lower()
        if ext in STATIC_ASSET_EXT:
            return None
    segs = [s for s in parts.path.split("/") if s]
    if not segs or len(segs) > 8:
        return None
    return segs


def _shape_of(segments: list[str]) -> tuple[str, ...] | None:
    """Turn real segments into a shape: literal words kept, IDs become
    the placeholder. Returns None if the path is mostly noise (can't
    classify most segments as either a clean word or a clear ID)."""
    shape = []
    unclassified = 0
    for seg in segments:
        if _looks_like_id(seg):
            shape.append(ID_PLACEHOLDER)
        elif _looks_like_word(seg):
            shape.append(seg.lower())
        else:
            unclassified += 1
            shape.append(None)  # placeholder, filtered below
    if unclassified > len(segments) / 2:
        return None
    if all(s == ID_PLACEHOLDER for s in shape if s):
        return None
    return tuple(shape)


@dataclass
class PathPrediction:
    path: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"path": self.path, "evidence": self.evidence}


def learn_grammar(urls: list[str], target_domain: str | None = None) -> dict:
    """Read real discovered URLs and learn this target's own structural
    vocabulary. Returns a dict used both for prediction and for
    inspection/debugging (why a candidate got generated).

    target_domain, if given, restricts learning to that domain and its
    subdomains — see in_scope()'s docstring for why this matters."""
    observed_shapes: set[tuple[str, ...]] = set()
    observed_paths: set[str] = set()
    # word -> which shape-position(s) (shape length, index) it was seen in
    word_positions: dict[str, set[tuple[int, int]]] = defaultdict(set)
    # trailing single-word "leaf" endpoints under a resource:
    # resource_word -> set of trailing action words seen directly under it
    resource_actions: dict[str, set[str]] = defaultdict(set)
    # every resource word seen immediately before an {id} segment, even
    # if no action was ever observed after that id (e.g. "/invoices/701"
    # with nothing after it) — these still deserve predicted actions
    # cross-pollinated from OTHER resources, so they must be tracked
    # separately from resource_actions (which only holds resources that
    # already have >=1 observed action).
    id_bearing_resources: set[str] = set()
    action_examples: dict[str, str] = {}  # action word -> one real URL it came from
    resource_examples: dict[str, str] = {}
    # resource_word -> one real id VALUE seen directly after it, so a
    # prediction like "/invoices/{id}/delivery" can become an actually
    # fetchable "/invoices/701/delivery" — ffuf has no way to test a
    # literal "{id}" token, it needs a concrete value from this target.
    resource_sample_id: dict[str, str] = {}

    scanned = 0
    for url in urls:
        if scanned >= MAX_URLS_SCANNED:
            break
        if not in_scope(url, target_domain):
            continue
        segs = _split_path(url)
        if not segs:
            continue
        scanned += 1
        shape = _shape_of(segs)
        if not shape:
            continue
        observed_shapes.add(shape)
        observed_paths.add("/" + "/".join(segs))

        for i, (raw, sh) in enumerate(zip(segs, shape)):
            if sh and sh != ID_PLACEHOLDER:
                word_positions[sh].add((len(shape), i))
                resource_examples.setdefault(sh, url)

        # Resource/id relationship: literal segment immediately
        # followed by an ID, e.g. ["invoices", "{id}"] -> invoices is an
        # id-bearing resource, regardless of whether anything follows.
        for i in range(len(shape) - 1):
            if shape[i] and shape[i] != ID_PLACEHOLDER and shape[i + 1] == ID_PLACEHOLDER:
                id_bearing_resources.add(shape[i])
                if shape[i] not in resource_sample_id:
                    resource_sample_id[shape[i]] = segs[i + 1]
                # And if something comes after that id, that's an
                # observed action for this specific resource.
                if i + 2 < len(shape):
                    action = shape[i + 2]
                    if action and action != ID_PLACEHOLDER:
                        resource_actions[shape[i]].add(action)
                        action_examples.setdefault(action, url)

    return {
        "observed_shapes": observed_shapes,
        "observed_paths": observed_paths,
        "word_positions": word_positions,
        "resource_actions": resource_actions,
        "id_bearing_resources": id_bearing_resources,
        "resource_sample_id": resource_sample_id,
        "action_examples": action_examples,
        "resource_examples": resource_examples,
        "urls_scanned": scanned,
    }


def predict(grammar: dict, max_predictions: int = MAX_PREDICTIONS) -> list[PathPrediction]:
    """Cross-pollinate: for every resource that takes an id, and every
    action word this target uses on some OTHER resource, predict
    resource/{id}/action -- but only using words this exact target has
    demonstrably used somewhere else. Every prediction carries the real
    source URLs that justified it, plus a concrete fuzzable path with a
    real id substituted in (ffuf can't test a literal "{id}" token)."""
    resource_actions = grammar["resource_actions"]
    id_bearing_resources = grammar["id_bearing_resources"]
    resource_sample_id = grammar["resource_sample_id"]
    action_examples = grammar["action_examples"]
    resource_examples = grammar["resource_examples"]
    observed_shapes = grammar["observed_shapes"]

    all_actions: set[str] = set()
    for actions in resource_actions.values():
        all_actions |= actions

    predictions: list[PathPrediction] = []
    seen_candidates: set[str] = set()

    # Every resource that takes an id is a target for cross-pollinated
    # actions -- including ones with zero observed actions of their own
    # (e.g. "/invoices/{id}" that never showed a trailing verb).
    resources_sorted = sorted(id_bearing_resources)
    for resource in resources_sorted:
        already_has = resource_actions.get(resource, set())
        missing = sorted(all_actions - already_has)
        for action in missing:
            candidate = f"/{resource}/{ID_PLACEHOLDER}/{action}"
            if candidate in seen_candidates:
                continue
            if (resource, ID_PLACEHOLDER, action) in observed_shapes:
                continue  # already directly observed, not a new lead
            seen_candidates.add(candidate)
            sample_id = resource_sample_id.get(resource)
            fuzz_path = f"{resource}/{sample_id}/{action}" if sample_id else None
            predictions.append(PathPrediction(
                path=candidate,
                evidence={
                    "kind": "cross_resource_action",
                    "resource_seen_in": resource_examples.get(resource, ""),
                    "action_seen_in": action_examples.get(action, ""),
                    "sample_id_used": sample_id or "",
                    "fuzz_path": fuzz_path or "",
                    "reason": (
                        f"'{resource}' is a resource this target exposes with an "
                        f"id (like {resource_examples.get(resource, '')!r}); "
                        f"'{action}' is an action this target uses on a "
                        f"*different* resource (like "
                        f"{action_examples.get(action, '')!r}). Neither word is "
                        f"from a generic list -- both are this target's own "
                        f"vocabulary, just never observed combined this way."
                    ),
                },
            ))
            if len(predictions) >= max_predictions:
                return predictions
    return predictions


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--urls-file", default=None,
                     help="defaults to <results-dir>/urls/all.txt")
    ap.add_argument("--target", default=None,
                     help="base domain to restrict learning to (e.g. "
                          "superdrug.com); defaults to target_profile.json's "
                          "\"target\" field if present, else no filtering")
    ap.add_argument("--max-predictions", type=int, default=MAX_PREDICTIONS)
    args = ap.parse_args()

    urls_path = args.urls_file or os.path.join(args.results_dir, "urls", "all.txt")
    out_dir = os.path.join(args.results_dir, "detection")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "predicted_paths.json")

    target_domain = args.target
    if not target_domain:
        profile_path = os.path.join(args.results_dir, "smart-fuzzing", "target_profile.json")
        if os.path.isfile(profile_path):
            try:
                with open(profile_path) as f:
                    target_domain = json.load(f).get("target")
            except (json.JSONDecodeError, OSError):
                target_domain = None

    urls: list[str] = []
    if os.path.isfile(urls_path):
        with open(urls_path, "r", errors="ignore") as f:
            urls = [l.strip() for l in f if l.strip()]

    grammar = learn_grammar(urls, target_domain=target_domain)
    predictions = predict(grammar, args.max_predictions)

    with open(out_path, "w") as f:
        json.dump([p.to_dict() for p in predictions], f, indent=2)

    scope_note = f", scoped to '{target_domain}'" if target_domain else " (unscoped — no target domain found)"
    print(
        f"✅ predicted_paths.json written ({len(predictions)} predictions from "
        f"{len(grammar['observed_shapes'])} learned shapes over "
        f"{grammar['urls_scanned']} scanned URLs{scope_note}) -> {out_path}"
    )


if __name__ == "__main__":
    main()
