#!/usr/bin/env python3
"""export_sra_handoff.py — BBCI → SRA consumer projection (NOT the Research Agent).

Reads a BugBountyCI results directory and writes meta/sra_handoff.json in the
fixture shape expected by security-research-agent ReconResultAdapter /
bbci_contract.normalize_bbci_artifact:

  primary_host, hosts, endpoints[{method,path,host}], technologies, urls, source

Does NOT import SRA code. Does NOT claim vulnerabilities. Boundary:
  BugBountyCI → this projection → (external) ReconResultAdapter → SRA
"""
from __future__ import annotations

import argparse
import json
import os
import re
from urllib.parse import urlparse


def _load_json(path: str):
    if not os.path.isfile(path):
        return None
    with open(path, "r", errors="ignore") as f:
        return json.load(f)


def _load_jsonl(path: str, limit: int = 5000) -> list:
    if not os.path.isfile(path):
        return []
    rows = []
    with open(path, "r", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _host_from_url(u: str) -> str:
    try:
        return (urlparse(u).hostname or "").lower()
    except Exception:
        return ""


def _path_from_url(u: str) -> str:
    try:
        p = urlparse(u)
        path = p.path or "/"
        if p.query:
            return path  # params tracked separately; path only for endpoint identity
        return path
    except Exception:
        return u if u.startswith("/") else "/"


def build_handoff(results_dir: str) -> dict:
    rd = results_dir
    rexp = _load_json(os.path.join(rd, "meta", "recon_export.json")) or {}
    tp = _load_json(os.path.join(rd, "meta", "target_profile.json")) or {}
    eh = _load_json(os.path.join(rd, "meta", "engine_health.json")) or {}

    target = (
        str(rexp.get("target") or tp.get("target") or "").strip()
        or "unknown"
    )
    run_id = str(rexp.get("run_id") or tp.get("run_id") or "").strip()

    hosts: list[str] = []
    for row in _load_jsonl(os.path.join(rd, "meta", "hosts.jsonl"), limit=2000):
        h = row.get("host") or row.get("hostname") or ""
        if h and h not in hosts:
            hosts.append(str(h).lower())
    if target and target not in hosts:
        hosts.insert(0, target)

    endpoints: list[dict] = []
    seen = set()

    def add_ep(method: str, path: str, host: str, params: list | None = None, provenance: str = ""):
        method = (method or "GET").upper()
        path = path or "/"
        host = (host or target or "").lower()
        key = (method, path, host)
        if key in seen:
            return
        if not path.startswith("/") and not path.startswith("http"):
            path = "/" + path
        # If absolute URL given as path, split
        if path.startswith("http"):
            host = _host_from_url(path) or host
            path = _path_from_url(path)
        seen.add(key)
        rec = {
            "method": method,
            "path": path[:300],
            "host": host,
            "auth_required": None,
            "parameters": params or [],
        }
        if provenance:
            rec["provenance"] = provenance[:200]
        endpoints.append(rec)

    # endpoints.jsonl
    for row in _load_jsonl(os.path.join(rd, "meta", "endpoints.jsonl")):
        ep = row.get("endpoint") or row.get("path") or row.get("url") or ""
        host = row.get("host") or _host_from_url(str(ep)) or target
        if str(ep).startswith("http"):
            add_ep("GET", str(ep), host, provenance=str(row.get("provenance") or "meta/endpoints.jsonl"))
        elif ep:
            add_ep("GET", str(ep), host, provenance=str(row.get("provenance") or "meta/endpoints.jsonl"))

    # parameters.jsonl → attach param names when path matches
    param_by_path: dict[str, list] = {}
    for row in _load_jsonl(os.path.join(rd, "meta", "parameters.jsonl")):
        path = row.get("path") or row.get("endpoint") or ""
        name = row.get("parameter") or row.get("name") or ""
        if path and name:
            param_by_path.setdefault(str(path), [])
            if name not in param_by_path[str(path)]:
                param_by_path[str(path)].append(str(name))

    # LinkFinder API routes (high research value for capital-like targets)
    lf = os.path.join(rd, "js_deep", "linkfinder_normalized.jsonl")
    for rec in _load_jsonl(lf, limit=8000):
        if rec.get("classification") != "API_ROUTE":
            continue
        raw = (rec.get("resolved_url") or rec.get("raw_value") or "").strip().rstrip("\\")
        if not raw or raw.lower().endswith((".js", ".css", ".map")):
            continue
        host = _host_from_url(raw) if raw.startswith("http") else target
        path = _path_from_url(raw) if raw.startswith("http") else (raw if raw.startswith("/") else "/" + raw)
        params = param_by_path.get(path) or param_by_path.get(raw) or []
        add_ep("GET", path, host or target, params=params, provenance="js_deep/linkfinder_normalized.jsonl")

    # urls.jsonl sample for surface (capped)
    urls = []
    for row in _load_jsonl(os.path.join(rd, "meta", "urls.jsonl"), limit=200):
        u = row.get("url") or row.get("value") or ""
        if u and u not in urls:
            urls.append(str(u)[:500])

    technologies = []
    for key in ("technologies", "tech", "stack"):
        v = tp.get(key) or rexp.get(key)
        if isinstance(v, list):
            technologies.extend(str(x) for x in v)

    handoff = {
        "schema": "bugbountyci.sra_handoff.v1",
        "recon_id": run_id or f"bbci-{target}",
        "source": "bugbountyci.recon_export.v1",
        "primary_host": target,
        "hosts": hosts[:500],
        "technologies": list(dict.fromkeys(technologies))[:100],
        "endpoints": endpoints[:400],
        "urls": urls[:200],
        "actors": [],
        "resources": [],
        "engine_health_overall": eh.get("overall"),
        "limitations": list(eh.get("flags") or [])[:20],
        "boundary": "BugBountyCI producer projection only; not SRA reasoning",
        "bbci_artifacts": {
            "recon_export": "meta/recon_export.json",
            "target_profile": "meta/target_profile.json",
            "hunter_queue": "detection/hunter_queue.md",
        },
    }
    return handoff


def minimal_contract_ok(doc: dict) -> tuple[bool, list[str]]:
    """Mirror SRA bbci_contract required field without importing SRA."""
    errs = []
    if not isinstance(doc, dict):
        return False, ["not_object"]
    if not str(doc.get("primary_host") or "").strip():
        errs.append("missing primary_host")
    if not isinstance(doc.get("endpoints"), list):
        errs.append("endpoints must be list")
    return (len(errs) == 0, errs)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    args = ap.parse_args(argv)
    rd = args.results_dir
    doc = build_handoff(rd)
    out = os.path.join(rd, "meta", "sra_handoff.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    ok, errs = minimal_contract_ok(doc)
    print(
        f"✅ sra_handoff: primary_host={doc.get('primary_host')} "
        f"hosts={len(doc.get('hosts') or [])} endpoints={len(doc.get('endpoints') or [])} "
        f"contract_ok={ok}"
    )
    if not ok:
        for e in errs:
            print(" ", e)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
