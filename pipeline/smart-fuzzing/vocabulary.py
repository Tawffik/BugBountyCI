#!/usr/bin/env python3
"""
vocabulary.py — V1

Extracts the application's own vocabulary from URLs, JS-discovered
endpoints, and known parameters, and records WHERE each word came from.
A word seen in JS + API + as a parameter is stronger evidence than a word
seen in one place — later steps (wolf_selector, wordlist_builder) use
that source count as a weight.

Output:
  <RD>/smart-fuzzing/vocabulary.json
    { "invoice": {"sources": ["js", "url", "parameter"], "count": 3}, ... }
"""
import argparse
import json
import os
import re
from collections import defaultdict

STOPWORDS = {
    "http", "https", "www", "com", "org", "net", "html", "htm", "php",
    "js", "css", "json", "xml", "index", "assets", "static", "public",
    "img", "images", "fonts", "node", "modules", "src", "dist", "build",
    "true", "false", "null", "undefined", "this", "self", "type", "id",
    "name", "value", "data", "get", "post", "put", "delete", "the", "and",
}

TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{2,}")


def read_lines(path):
    if not path or not os.path.isfile(path):
        return []
    with open(path, "r", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


def tokenize(text):
    """Split a URL/path/JS-endpoint string into candidate words.
    Handles camelCase, snake_case, kebab-case, and path segments."""
    # camelCase -> camel Case
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    # non-alnum -> space
    text = re.sub(r"[^A-Za-z0-9]+", " ", text)
    words = set()
    for tok in TOKEN_RE.findall(text):
        w = tok.lower()
        if w in STOPWORDS or len(w) < 3 or w.isdigit():
            continue
        words.add(w)
    return words


def add(vocab, words, source):
    for w in words:
        vocab[w]["sources"].add(source)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default="", help="target domain, so its own name/TLD "
                     "tokens (e.g. 'example', 'com') are excluded as noise")
    args = ap.parse_args()
    rd = args.results_dir

    domain_tokens = {t for t in re.split(r"[.\-]", args.target.lower()) if t}
    STOPWORDS.update(domain_tokens)
    out_dir = os.path.join(rd, "smart-fuzzing")
    os.makedirs(out_dir, exist_ok=True)

    vocab = defaultdict(lambda: {"sources": set()})

    js_endpoints = read_lines(os.path.join(rd, "js_deep", "linkfinder_endpoints.txt"))
    for line in js_endpoints:
        add(vocab, tokenize(line), "js")

    urls_all = read_lines(os.path.join(rd, "urls", "all.txt"))
    urls_gf = read_lines(os.path.join(rd, "urls", "gf_categorized.txt"))
    for line in urls_all + urls_gf:
        add(vocab, tokenize(line), "url")

    for f, source in (
        ("swagger.txt", "swagger"),
        ("graphql.txt", "graphql"),
        ("admin.txt", "admin"),
    ):
        for line in read_lines(os.path.join(rd, "js", f)):
            add(vocab, tokenize(line), source)

    params = read_lines(os.path.join(rd, "targeted", "arjun_params.txt"))
    for line in params:
        # arjun output is typically "param" or "param (url)" per line
        param_name = line.split()[0].strip().lower()
        if param_name and param_name not in STOPWORDS and len(param_name) >= 3:
            vocab[param_name]["sources"].add("parameter")

    result = {
        w: {"sources": sorted(v["sources"]), "count": len(v["sources"])}
        for w, v in vocab.items()
    }
    # Strongest evidence (most independent sources) first.
    result = dict(sorted(result.items(), key=lambda kv: kv[1]["count"], reverse=True))

    out_path = os.path.join(out_dir, "vocabulary.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"✅ vocabulary.json written ({len(result)} words) -> {out_path}")


if __name__ == "__main__":
    main()
