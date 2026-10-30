#!/usr/bin/env python3
"""Wide-collect → priority filter for Zero Track URL surface.

Does NOT delete urls/all.txt. Writes priority layers so heavy phases can
prefer sensitive paths without dropping inventory.

Outputs under urls/:
  priority_high.txt, priority_params.txt, priority_api.txt
  priority_inventory.txt (all not in high — optional sample)
meta/url_filter_stats.json
"""
from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import parse_qs, urlparse

# Extensions / suffixes — disclosure & maps
RE_EXT = re.compile(
    r"(?i)(\.env(?:\.[a-z0-9]+)?|\.git(?:/|$)|/\.git|\.svn|\.htaccess|\.htpasswd|"
    r"web\.config|appsettings\.json|\.bak|\.old|\.orig|\.swp|\.sql|\.dump|"
    r"\.(?:zip|tar|gz|tgz|7z|rar|log|pem|key|map)(?:\?|$)|"
    r"phpinfo|docker-compose|composer\.json|\.DS_Store)"
)

# Path keywords — auth, admin, api, cloud-ish, debug
RE_PATH = re.compile(
    r"(?i)/(?:api(?:/|$)|graphql|gql|swagger|openapi|api-docs|actuator|"
    r"admin(?:istrator)?|dashboard|manage|console|portal|staff|internal|"
    r"login|logout|signin|sign-in|signup|register|auth|oauth2?|authorize|"
    r"callback|sso|saml|oidc|token|session|password|reset|forgot|mfa|2fa|"
    r"account|profile|/me(?:/|$)|users?|debug|trace|profiler|phpmyadmin|"
    r"jenkins|gitlab|grafana|kibana|backup|backups|upload|download|export|"
    r"import|webhook|proxy|fetch|redirect|config|settings|env(?:/|$)|"
    r"metrics|health|status|booking|payment|checkout|invoice|patient|"
    r"appointment|onlinedoctor)"
)

# Query keys worth keeping even on bland paths
SENSITIVE_PARAMS = {
    "id", "user", "user_id", "uid", "account", "order", "file", "path", "url",
    "redirect", "next", "return", "returnurl", "callback", "dest", "target",
    "token", "key", "api_key", "access", "secret", "doc", "document", "download",
    "template", "ref", "ref_id", "continue", "goto",
}

RE_API_HOST_PATH = re.compile(
    r"(?i)(/api(?:/|$)|/graphql|/gql|/swagger|/openapi|/rest/|/v[0-9]+/)"
)
RE_JS = re.compile(r"(?i)\.js(?:\?|#|$)|/\.js\.map|\.js\.map(?:\?|$)")
RE_STATIC_NOISE = re.compile(
    r"(?i)\.(?:png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|css)(?:\?|$)"
)


def _params_sensitive(query: str) -> bool:
    if not query:
        return False
    try:
        qs = parse_qs(query, keep_blank_values=True)
    except Exception:
        return any(k in query.lower() for k in ("token=", "redirect=", "url=", "file="))
    for k in qs:
        if k.lower() in SENSITIVE_PARAMS:
            return True
    return False


def classify(url: str) -> set[str]:
    """Return tags: high, params, api, inventory."""
    tags: set[str] = set()
    u = url.strip()
    if not u or u.startswith("#"):
        return tags
    try:
        p = urlparse(u)
    except Exception:
        tags.add("high")
        return tags
    path = p.path or "/"
    full = u

    if RE_EXT.search(full) or RE_EXT.search(path):
        tags.add("high")
    if RE_PATH.search(path) or RE_PATH.search(full):
        tags.add("high")
    if RE_JS.search(full):
        tags.add("high")
    if _params_sensitive(p.query or ""):
        tags.add("high")
        tags.add("params")
    if RE_API_HOST_PATH.search(path) or RE_API_HOST_PATH.search(full):
        tags.add("high")
        tags.add("api")
    if "=" in u and "params" not in tags:
        # generic query — params list, high only if not pure static noise
        tags.add("params")
        if not RE_STATIC_NOISE.search(path):
            tags.add("high")

    if not tags:
        if RE_STATIC_NOISE.search(path):
            tags.add("inventory")
        else:
            # Prefer keep: unknown non-static → high (do not miss)
            tags.add("high")
    return tags


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: url_priority_filter.py <RESULTS_DIR>", file=sys.stderr)
        return 2
    rd = sys.argv[1]
    urls_dir = os.path.join(rd, "urls")
    meta_dir = os.path.join(rd, "meta")
    os.makedirs(urls_dir, exist_ok=True)
    os.makedirs(meta_dir, exist_ok=True)

    sources = []
    for name in (
        "all.txt",
        "wayback.txt",
        "gau.txt",
        "waymore.txt",
        "katana.txt",
        "html_extract.txt",
        "otx.txt",
        "urlscan.txt",
    ):
        path = os.path.join(urls_dir, name)
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            sources.append(path)

    seen: set[str] = set()
    high: list[str] = []
    params: list[str] = []
    api: list[str] = []
    inventory: list[str] = []
    raw_n = 0

    for sp in sources:
        with open(sp, "r", errors="replace") as f:
            for line in f:
                u = line.strip()
                if not u or u in seen:
                    continue
                seen.add(u)
                raw_n += 1
                tags = classify(u)
                if "high" in tags:
                    high.append(u)
                if "params" in tags:
                    params.append(u)
                if "api" in tags:
                    api.append(u)
                if "inventory" in tags and "high" not in tags:
                    inventory.append(u)
                elif "high" not in tags and "params" not in tags:
                    inventory.append(u)

    def wlines(path: str, rows: list[str]) -> int:
        with open(path, "w") as f:
            f.write("\n".join(rows))
            if rows:
                f.write("\n")
        return len(rows)

    n_high = wlines(os.path.join(urls_dir, "priority_high.txt"), high)
    n_params = wlines(os.path.join(urls_dir, "priority_params.txt"), params)
    n_api = wlines(os.path.join(urls_dir, "priority_api.txt"), api)
    n_inv = wlines(os.path.join(urls_dir, "priority_inventory.txt"), inventory)

    # Prefer juicy overlap: merge existing juicy into high if present
    juicy_p = os.path.join(urls_dir, "juicy.txt")
    if os.path.isfile(juicy_p):
        extra = []
        with open(juicy_p, "r", errors="replace") as f:
            for line in f:
                u = line.strip()
                if u and u not in seen:
                    extra.append(u)
                elif u and u not in high:
                    high.append(u)
        if extra or True:
            # re-write high unique
            high_u = list(dict.fromkeys(high))
            n_high = wlines(os.path.join(urls_dir, "priority_high.txt"), high_u)

    stats = {
        "schema": "bugbountyci.url_priority_filter.v1",
        "sources_scanned": [os.path.basename(s) for s in sources],
        "unique_urls_scanned": raw_n,
        "priority_high": n_high,
        "priority_params": n_params,
        "priority_api": n_api,
        "priority_inventory": n_inv,
        "note": (
            "Wide collect + keep-important filter. "
            "high prefers disclosure/auth/api/js/maps/params; "
            "does not shrink urls/all.txt. Unknown non-static → high (avoid misses)."
        ),
    }
    with open(os.path.join(meta_dir, "url_filter_stats.json"), "w") as f:
        json.dump(stats, f, indent=2)
        f.write("\n")
    print(
        f"✅ url_priority_filter: scanned={raw_n} high={n_high} "
        f"params={n_params} api={n_api} inventory={n_inv}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
