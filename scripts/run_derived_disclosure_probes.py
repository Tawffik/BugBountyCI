#!/usr/bin/env python3
"""P1a: stage-derived disclosure probes (JS→.map, path→backup siblings).

Budget-capped. Uses classify_info_disclosure_body. Never CONFIRMED.
See docs/INFO_DISCLOSURE_EXECUTION_PLAN.md Phase 2.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin, urlparse

# Import classifier
_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))
from classify_info_disclosure_body import classify_fixed_path_body  # noqa: E402

DEFAULT_BUDGET = 80
BACKUP_SUFFIXES = (".bak", ".old", ".orig", "~")
MAP_SUFFIX = ".map"
UA = os.environ.get("SCAN_USER_AGENT", "Mozilla/5.0 BugBountyCI-derived-disclosure/1.0")


def _lines(path: Path, limit: int = 5000) -> list[str]:
    if not path.is_file():
        return []
    out = []
    try:
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
            s = ln.strip()
            if s:
                out.append(s)
            if len(out) >= limit:
                break
    except OSError:
        return []
    return out


def _abs_http(u: str) -> bool:
    return u.startswith("http://") or u.startswith("https://")


def candidates_from_js(rd: Path, cap: int) -> list[tuple[str, str]]:
    """Return (url, kind) for .map probes."""
    files = _lines(rd / "js" / "files.txt", limit=2000)
    out: list[tuple[str, str]] = []
    seen = set()
    for u in files:
        if not _abs_http(u):
            continue
        if u.endswith(".map"):
            continue
        if not any(u.endswith(ext) for ext in (".js", ".mjs", ".cjs")):
            # still try if path looks like JS bundle without query
            path = urlparse(u).path.lower()
            if not path.endswith((".js", ".mjs", ".cjs")):
                continue
        base = u.split("?", 1)[0]
        target = base + MAP_SUFFIX
        if target in seen:
            continue
        seen.add(target)
        out.append((target, "source_map"))
        if len(out) >= cap:
            break
    return out


def candidates_from_paths(rd: Path, cap: int) -> list[tuple[str, str]]:
    """Backup siblings for absolute http(s) endpoints/paths with host."""
    raw: list[str] = []
    raw += _lines(rd / "js" / "endpoints.txt", limit=1500)
    # live hosts as prefix for relative paths
    hosts = []
    for h in _lines(rd / "live" / "hostname_targets.txt", limit=80):
        if _abs_http(h):
            hosts.append(h.rstrip("/") + "/")
    abs_urls = [u for u in raw if _abs_http(u)]
    rels = [u for u in raw if u.startswith("/") and not u.startswith("//")]
    for rel in rels[:200]:
        for host in hosts[:15]:
            abs_urls.append(urljoin(host, rel.lstrip("/")))
    out: list[tuple[str, str]] = []
    seen = set()
    for u in abs_urls:
        if not _abs_http(u):
            continue
        p = urlparse(u)
        path = p.path or "/"
        if path.endswith("/") or len(path) < 2:
            continue
        # skip already backup-like
        if any(path.endswith(sfx) or path.endswith(sfx.rstrip("~")) for sfx in (".bak", ".old", ".orig")):
            continue
        for sfx in BACKUP_SUFFIXES:
            if sfx == "~":
                new_path = path + "~"
            else:
                new_path = path + sfx
            target = p._replace(path=new_path, query="", fragment="").geturl()
            if target in seen:
                continue
            seen.add(target)
            out.append((target, "backup_sibling"))
            if len(out) >= cap:
                return out
    return out


def probe(url: str, timeout: float = 6.0) -> tuple[int | None, str, str]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": UA, "Accept": "*/*"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read(8192)
            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                text = body.decode("latin-1", errors="replace")
            return int(status), ctype, text
    except urllib.error.HTTPError as e:
        try:
            body = e.read(8192)
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        ctype = e.headers.get("Content-Type", "") if e.headers else ""
        return int(e.code), ctype, text
    except Exception as e:
        return None, "", f""


def interesting(disposition: str) -> bool:
    return disposition in ("CONTENT_SUPPORTED", "PATH_LEAD")


def run(rd: Path, budget: int, target: str) -> dict:
    idir = rd / "info_disclosure"
    idir.mkdir(parents=True, exist_ok=True)
    map_cap = max(10, budget // 2)
    bak_cap = budget - map_cap
    cands = candidates_from_js(rd, map_cap) + candidates_from_paths(rd, bak_cap)
    cands = cands[:budget]

    results = []
    map_hits: list[str] = []
    bak_hits: list[str] = []

    for url, kind in cands:
        status, ctype, body = probe(url)
        path_hint = urlparse(url).path if url else kind
        clf = classify_fixed_path_body(
            path_hint if kind != "source_map" else path_hint + ".map",
            body if status is not None else None,
            status_code=status,
            content_type=ctype,
            body_truncated=True,
        )
        disp = clf.get("disposition") or "INCONCLUSIVE"
        row = {
            "schema": "bugbountyci.derived_disclosure_probe.v1",
            "url": url,
            "kind": kind,
            "status": status,
            "content_type": ctype[:80] if ctype else "",
            "disposition": disp,
            "confidence": clf.get("confidence"),
            "reasons": clf.get("reasons") or [],
            "never_confirmed": True,
            "target": target,
        }
        results.append(row)
        # Record content-supported or strong map JSON
        if kind == "source_map" and status and 200 <= status < 400:
            if disp == "CONTENT_SUPPORTED" or (
                body and ("\"mappings\"" in body or body.strip().startswith("{") and "version" in body[:200])
            ):
                map_hits.append(url)
                row["disposition"] = row.get("disposition") or "CONTENT_SUPPORTED"
        if kind == "backup_sibling" and disp == "CONTENT_SUPPORTED":
            bak_hits.append(f"[DERIVED-BACKUP] {url} ({disp})")

    out_jsonl = idir / "derived_probes.jsonl"
    with out_jsonl.open("w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Append map hits
    sm_dir = rd / "source_maps"
    sm_dir.mkdir(parents=True, exist_ok=True)
    sm_file = sm_dir / "found.txt"
    existing = set(_lines(sm_file, limit=10000))
    with sm_file.open("a", encoding="utf-8") as fh:
        for u in map_hits:
            if u not in existing:
                fh.write(u + "\n")

    bak_file = idir / "backup_files.txt"
    with bak_file.open("a", encoding="utf-8") as fh:
        for line in bak_hits:
            fh.write(line + "\n")

    summary = {
        "schema": "bugbountyci.derived_disclosure_summary.v1",
        "budget": budget,
        "planned": len(cands),
        "probed": len(results),
        "map_hits": len(map_hits),
        "backup_content_hits": len(bak_hits),
        "by_disposition": {},
        "note": "Derived probes only; never CONFIRMED. HTML/WAF dispositions are noise.",
    }
    for r in results:
        d = r.get("disposition") or "?"
        summary["by_disposition"][d] = summary["by_disposition"].get(d, 0) + 1

    (idir / "derived_probes_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    phase = {
        "schema": "bugbountyci.phase.v1",
        "phase": "derived_disclosure",
        "status": "ok",
        "detail": f"probed={summary['probed']} map_hits={summary['map_hits']} bak={summary['backup_content_hits']}",
        "counts": {
            "probed": summary["probed"],
            "map_hits": summary["map_hits"],
            "backup_content_hits": summary["backup_content_hits"],
        },
    }
    (rd / "meta" / "phases").mkdir(parents=True, exist_ok=True)
    (rd / "meta" / "phases" / "derived_disclosure.json").write_text(
        json.dumps(phase, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"ok": True, **{k: summary[k] for k in ("probed", "map_hits", "backup_content_hits", "by_disposition")}}))
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--target", default="")
    ap.add_argument("--budget", type=int, default=int(os.environ.get("DERIVED_DISCLOSURE_BUDGET", DEFAULT_BUDGET)))
    args = ap.parse_args()
    rd = Path(args.results_dir)
    if not rd.is_dir():
        print(json.dumps({"ok": False, "error": "results_dir missing"}))
        return 0
    run(rd, max(5, min(args.budget, 120)), args.target or "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
