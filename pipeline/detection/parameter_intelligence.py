#!/usr/bin/env python3
"""
Parameter Intelligence — Priority 1 foundation.

Builds a single endpoint → parameters map from existing recon artifacts
so future engines (IDOR/SSRF/injection) do not each re-parse urls/all.txt.

Sources (all optional; missing files are skipped):
  - targeted/arjun_params.txt
  - urls/params.txt
  - js/api_endpoints.txt
  - js/swagger.txt / js/graphql.txt (path hints)
  - urls/gf_categorized.txt (lines that look like URLs with query strings)
  - smart-fuzzing/vocabulary.json (param-like tokens as weak hints)

Output: detection/parameter_intelligence.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse, parse_qs, unquote

# Cap noise: unbounded param maps have burned this project before.
MAX_ENDPOINTS = 2000
MAX_PARAMS_PER_ENDPOINT = 80
MAX_LINE_SCAN = 50000

PARAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,64}$")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def _endpoint_in_scope(endpoint: str, target_domain: str | None) -> bool:
    """Keep only the authorized target and its subdomains.

    Same failure class as pattern_predictor.in_scope: wayback/gau/gf lists
    contain third-party domains the target merely links to. Without filtering,
    SSRF/open-redirect candidates can target hosts outside authorized scope.
    """
    if not target_domain:
        return True
    if not endpoint or endpoint == "_global":
        return True
    if endpoint.startswith("/"):
        return True
    try:
        host = (urlparse(endpoint).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    # trailing dots (DNS absolute form) must not break equality
    host = host.rstrip(".")
    td = target_domain.lower().strip(".").lstrip(".")
    if not td:
        return True
    return host == td or host.endswith("." + td)



def _read_lines(path: str, limit: int = MAX_LINE_SCAN) -> list[str]:
    if not path or not os.path.isfile(path) or os.path.getsize(path) == 0:
        return []
    out: list[str] = []
    with open(path, "r", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def _norm_endpoint(url: str) -> str | None:
    url = url.strip().rstrip(",;")
    if not url or url.startswith("#"):
        return None
    # strip obvious status suffixes from some lists: "https://x [200]"
    url = re.split(r"\s+\[", url, 1)[0].strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        if url.startswith("/") or "://" not in url:
            # path-only: keep as relative key
            path = url.split("?")[0]
            return path if path.startswith("/") else None
        return None
    try:
        p = urlparse(url)
        if not p.netloc:
            return None
        path = p.path or "/"
        # drop fragments; query handled separately
        return f"{p.scheme}://{p.netloc}{path}"
    except Exception:
        return None


def _params_from_url(url: str) -> list[str]:
    try:
        q = urlparse(url).query
        if not q:
            return []
        names = []
        for k in parse_qs(q, keep_blank_values=True).keys():
            k = unquote(k)
            if PARAM_NAME_RE.match(k):
                names.append(k)
        return names
    except Exception:
        return []


def _add(store: dict, endpoint: str, param: str, source: str) -> None:
    if not endpoint or not param or not PARAM_NAME_RE.match(param):
        return
    bucket = store[endpoint]
    if param not in bucket and len(bucket) < MAX_PARAMS_PER_ENDPOINT:
        bucket[param] = set()
    if param in bucket:
        bucket[param].add(source)


def resolve_target_domain(
    results_dir: str,
    explicit: str | None = None,
) -> str | None:
    """Resolve authorized target host for scope filtering.

    Order: explicit arg → TARGET env → smart-fuzzing/target_profile.json
    → detection/target.txt. Empty strings are treated as absent so a lost
    env var does not silently mean "no filter" when a profile exists.
    """
    if explicit and str(explicit).strip():
        return str(explicit).strip().lower().strip(".").lstrip(".")
    env = (os.environ.get("TARGET") or "").strip()
    if env:
        return env.lower().strip(".").lstrip(".")
    profile_path = os.path.join(results_dir, "smart-fuzzing", "target_profile.json")
    if os.path.isfile(profile_path):
        try:
            with open(profile_path, encoding="utf-8", errors="replace") as f:
                t = (json.load(f) or {}).get("target")
            if t and str(t).strip():
                return str(t).strip().lower().strip(".").lstrip(".")
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    for rel in ("detection/target.txt", "meta/target.txt", "target.txt"):
        tp = os.path.join(results_dir, rel)
        if os.path.isfile(tp):
            try:
                line = open(tp, encoding="utf-8", errors="replace").readline().strip()
                if line:
                    return line.lower().strip(".").lstrip(".")
            except OSError:
                pass
    return None


def build(results_dir: str, target_domain: str | None = None) -> dict[str, Any]:
    rd = results_dir
    store: dict[str, dict[str, set]] = defaultdict(dict)

    # Arjun: often "url param1 param2" or "url?a=1&b=2"
    for line in _read_lines(os.path.join(rd, "targeted", "arjun_params.txt")):
        parts = line.split()
        if not parts:
            continue
        ep = _norm_endpoint(parts[0])
        if not ep:
            continue
        for p in _params_from_url(parts[0]):
            _add(store, ep, p, "arjun")
        for tok in parts[1:]:
            tok = tok.strip(",").split("=")[0]
            _add(store, ep, tok, "arjun")

    # urls/params.txt — mixed formats
    for line in _read_lines(os.path.join(rd, "urls", "params.txt")):
        for m in URL_RE.findall(line):
            ep = _norm_endpoint(m)
            if not ep:
                continue
            for p in _params_from_url(m):
                _add(store, ep, p, "urls/params")
        # bare param names (one per line)
        if "?" not in line and "://" not in line and PARAM_NAME_RE.match(line):
            _add(store, "_global", line, "urls/params")

    # JS API endpoints
    for line in _read_lines(os.path.join(rd, "js", "api_endpoints.txt")):
        for m in URL_RE.findall(line) or ([line] if line.startswith("http") or line.startswith("/") else []):
            ep = _norm_endpoint(m if m.startswith("http") else line)
            if not ep:
                # path-only from JS
                path = line.split()[0].split("?")[0]
                if path.startswith("/") and len(path) < 200:
                    ep = path
                else:
                    continue
            for p in _params_from_url(line if "?" in line else (m if "?" in m else "")):
                _add(store, ep, p, "js/api_endpoints")
            if "?" not in line and ep:
                store.setdefault(ep, store.get(ep, {}))

    for name, src in (("swagger.txt", "js/swagger"), ("graphql.txt", "js/graphql")):
        for line in _read_lines(os.path.join(rd, "js", name)):
            for m in URL_RE.findall(line):
                ep = _norm_endpoint(m)
                if ep:
                    for p in _params_from_url(m):
                        _add(store, ep, p, src)
                    store.setdefault(ep, store.get(ep, {}))

    for line in _read_lines(os.path.join(rd, "urls", "gf_categorized.txt"), limit=20000):
        for m in URL_RE.findall(line):
            ep = _norm_endpoint(m)
            if not ep:
                continue
            for p in _params_from_url(m):
                _add(store, ep, p, "gf_categorized")

    # vocabulary: weak global hints only (cap)
    vocab_path = os.path.join(rd, "smart-fuzzing", "vocabulary.json")
    if os.path.isfile(vocab_path):
        try:
            raw = json.load(open(vocab_path, errors="replace"))
            words = raw if isinstance(raw, list) else raw.get("words") or raw.get("vocabulary") or []
            count = 0
            for w in words:
                if count >= 100:
                    break
                if isinstance(w, dict):
                    w = w.get("word") or w.get("term") or ""
                if isinstance(w, str) and PARAM_NAME_RE.match(w) and any(
                    x in w.lower() for x in ("id", "url", "redirect", "token", "key", "file", "path", "callback", "next")
                ):
                    _add(store, "_global", w, "vocabulary")
                    count += 1
        except (json.JSONDecodeError, OSError):
            pass

    endpoints_out = []
    dropped_oos = 0
    for ep, params in store.items():
        if ep == "_global":
            continue
        if not _endpoint_in_scope(ep, target_domain):
            dropped_oos += 1
            continue
        endpoints_out.append({
            "endpoint": ep,
            "parameters": [
                {"name": n, "sources": sorted(srcs)}
                for n, srcs in sorted(params.items())
            ],
        })
    # Cap after scope filter so MAX_ENDPOINTS is in-scope budget
    endpoints_out = endpoints_out[:MAX_ENDPOINTS]
    endpoints_out.sort(key=lambda e: (-len(e["parameters"]), e["endpoint"]))

    global_params = [
        {"name": n, "sources": sorted(srcs)}
        for n, srcs in sorted(store.get("_global", {}).items())
    ]

    return {
        "version": 1,
        "target_domain": target_domain or "",
        "scope_mode": "scoped" if target_domain else "unscoped",
        "endpoint_count": len(endpoints_out),
        "parameter_count": sum(len(e["parameters"]) for e in endpoints_out) + len(global_params),
        "endpoints_dropped_out_of_scope": dropped_oos,
        "global_parameter_hints": global_params,
        "endpoints": endpoints_out,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Build parameter intelligence map from recon artifacts")
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default=None, help="authorized domain (default: TARGET env or target_profile)")
    ap.add_argument("--out", default=None, help="default: <results-dir>/detection/parameter_intelligence.json")
    args = ap.parse_args()
    target = resolve_target_domain(args.results_dir, explicit=args.target)
    data = build(args.results_dir, target_domain=target)
    out = args.out or os.path.join(args.results_dir, "detection", "parameter_intelligence.json")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    oos = data.get("endpoints_dropped_out_of_scope") or 0
    mode = data.get("scope_mode") or "unscoped"
    td = data.get("target_domain") or ""
    scope_note = f", scope={mode}" + (f"({td})" if td else "")
    if mode == "unscoped":
        scope_note += " — no TARGET/profile; third-party endpoints not filtered"
    print(
        f"✅ parameter_intelligence.json: {data['endpoint_count']} endpoints, "
        f"{data['parameter_count']} params"
        f"{f', dropped_oos={oos}' if oos else ''}{scope_note} → {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
