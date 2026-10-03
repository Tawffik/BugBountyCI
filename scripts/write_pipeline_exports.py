#!/usr/bin/env python3
"""Write pipeline meta exports: health, profile, hosts, observations, surface, vocabulary, relationships.
Called from Pipeline Health Report after pipeline_health.md is written.
Does not replace raw evidence.
"""
import json, glob, os, re, sys
from urllib.parse import urlparse

def main():
    rd = sys.argv[1] if len(sys.argv) > 1 else f"results/{os.environ.get('TIMESTAMP','')}"
    target = os.environ.get("TARGET", "")
    run_id = os.environ.get("TIMESTAMP", "")
    os.makedirs(os.path.join(rd, "meta"), exist_ok=True)

    phases = {}
    for pf in glob.glob(os.path.join(rd, "meta", "phases", "*.json")):
        try:
            with open(pf) as fh:
                j = json.load(fh)
            phases[j.get("phase") or os.path.basename(pf).replace(".json", "")] = j
        except Exception:
            pass

    flags = []
    # re-derive minimal flags from phases for machine health
    arj = phases.get("arjun") or {}
    if str(arj.get("status", "")).upper() in ("PARTIAL", "ERROR"):
        flags.append(f"Arjun phase={arj.get('status')} — {arj.get('detail','')}")
    nuc = phases.get("nuclei") or {}
    if str(nuc.get("status", "")).upper() == "PARTIAL":
        flags.append(f"Nuclei phase=PARTIAL — {nuc.get('detail','')}")

    overall = "DEGRADED" if flags else "OK"
    # prefer pipeline_health first line if present
    ph = os.path.join(rd, "meta", "pipeline_health.md")
    if os.path.exists(ph):
        try:
            for line in open(ph):
                if line.startswith("## Overall:"):
                    overall = line.split("## Overall:", 1)[1].strip()
                    break
        except Exception:
            pass

    eng = {
        "schema": "bugbountyci.engine_health.v1",
        "run_id": run_id,
        "overall": overall,
        "phases": phases,
        "flags": flags,
    }
    with open(os.path.join(rd, "meta", "engine_health.json"), "w") as fh:
        json.dump(eng, fh, indent=2)
        fh.write("\n")

    def nlines(p):
        try:
            with open(os.path.join(rd, p)) as fh:
                return sum(1 for l in fh if l.strip())
        except Exception:
            return 0

    # hosts
    resolved = set()
    live_urls = []
    verified = set()
    ports_by_ip = {}
    try:
        with open(os.path.join(rd, "subdomains/resolved.txt")) as fh:
            resolved = {l.strip().lower() for l in fh if l.strip()}
    except Exception:
        pass
    try:
        with open(os.path.join(rd, "live/verified.txt")) as fh:
            for l in fh:
                u = l.strip()
                if not u:
                    continue
                verified.add(u)
                live_urls.append(u)
    except Exception:
        pass
    try:
        with open(os.path.join(rd, "live/live.txt")) as fh:
            for l in fh:
                u = l.strip()
                if u and u not in verified:
                    live_urls.append(u)
    except Exception:
        pass
    try:
        with open(os.path.join(rd, "live/ports.txt")) as fh:
            for l in fh:
                l = l.strip()
                if ":" not in l:
                    continue
                ip, port = l.rsplit(":", 1)
                ports_by_ip.setdefault(ip, set()).add(port)
    except Exception:
        pass

    hosts = []
    seen = set()
    for u in live_urls:
        try:
            p = urlparse(u if "://" in u else "http://" + u)
        except Exception:
            continue
        host = (p.hostname or "").lower()
        if not host or host in seen:
            continue
        seen.add(host)
        is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
        host_ports = sorted(ports_by_ip.get(host, [])) if is_ip else []
        host_class = "VERIFIED_HTTP" if any(
            (urlparse(v).hostname or "").lower() == host for v in verified
        ) else "LIVE_HTTP"
        hosts.append({
            "schema": "bugbountyci.host.v1",
            "run_id": run_id,
            "target": target,
            "hostname": host,
            "is_ip": is_ip,
            "dns_resolved": (not is_ip) and (host in resolved),
            "host_class": host_class,
            "reachability": "REACHABLE",
            "sample_url": u,
            "open_ports": host_ports,
            "provenance": "live/verified+live.txt+ports.txt+resolved.txt",
        })
    with open(os.path.join(rd, "meta", "hosts.jsonl"), "w") as fh:
        for h in hosts:
            fh.write(json.dumps(h) + "\n")

    # observations
    observations = []
    def add_obs(**kw):
        o = {"schema": "bugbountyci.observation.v1", "run_id": run_id}
        o.update(kw)
        observations.append(o)
    try:
        with open(os.path.join(rd, "targeted/arjun_params.txt")) as fh:
            for i, l in enumerate(fh):
                l = l.strip()
                if not l:
                    continue
                add_obs(
                    observation_id=f"arjun-{i}",
                    engine="arjun",
                    observed_behavior="parameter_candidate",
                    status=(phases.get("arjun") or {}).get("status", "UNKNOWN"),
                    sample=l[:300],
                    classification="LEAD",
                    confidence="low",
                    limitations="upstream tool errors possible; not confirmed",
                    provenance="targeted/arjun_params.txt",
                )
    except Exception:
        pass
    try:
        with open(os.path.join(rd, "nuclei/findings.jsonl")) as fh:
            for i, l in enumerate(fh):
                if not l.strip():
                    continue
                try:
                    j = json.loads(l)
                except Exception:
                    continue
                info = j.get("info") or {}
                add_obs(
                    observation_id=f"nuclei-{i}",
                    engine="nuclei",
                    url=j.get("matched-at") or j.get("host"),
                    observed_behavior=info.get("name") or "finding",
                    status="SUCCESS",
                    classification="SIGNAL",
                    confidence=str(info.get("severity") or "unknown"),
                    provenance="nuclei/findings.jsonl",
                )
    except Exception:
        pass
    for rel in ("smart-fuzzing/interesting.txt", "fuzzing/interesting.txt"):
        p = os.path.join(rd, rel)
        if not os.path.exists(p):
            continue
        try:
            with open(p) as fh:
                for i, l in enumerate(fh):
                    if not l.strip():
                        continue
                    add_obs(
                        observation_id=f"smart_fuzz-{i}",
                        engine="smart_fuzzing",
                        observed_behavior="interesting_response",
                        status="SUCCESS",
                        sample=l.strip()[:400],
                        classification="LEAD",
                        confidence="low",
                        provenance=rel,
                    )
        except Exception:
            pass
        break
    for eng, ph in phases.items():
        st = (ph or {}).get("status") or ""
        if st.upper() in ("PARTIAL", "ERROR", "EMPTY") or st.lower() in ("partial", "error", "empty"):
            add_obs(
                observation_id=f"phase-{eng}",
                engine=eng,
                observed_behavior="phase_status",
                status=st,
                classification="HEALTH",
                confidence="high",
                detail=(ph or {}).get("detail"),
                provenance=f"meta/phases/{eng}.json",
            )
    with open(os.path.join(rd, "meta", "observations.jsonl"), "w") as fh:
        for o in observations:
            fh.write(json.dumps(o, default=str) + "\n")

    # --- urls.jsonl (capped; path/host normalized) ---
    urls_rows = []
    try:
        with open(os.path.join(rd, "urls/all.txt")) as fh:
            for i, line in enumerate(fh):
                if i >= 5000:
                    break
                u = line.strip().split()[0] if line.strip() else ""
                if not u.startswith("http"):
                    continue
                try:
                    p = urlparse(u)
                except Exception:
                    continue
                host = (p.hostname or "").lower()
                if not host:
                    continue
                urls_rows.append({
                    "schema": "bugbountyci.url.v1",
                    "run_id": run_id,
                    "target": target,
                    "url": u[:500],
                    "host": host,
                    "scheme": (p.scheme or "").lower(),
                    "path": p.path or "/",
                    "has_query": bool(p.query),
                    "provenance": "urls/all.txt",
                })
    except Exception:
        pass
    with open(os.path.join(rd, "meta", "urls.jsonl"), "w") as fh:
        for row in urls_rows:
            fh.write(json.dumps(row) + "\n")

    # --- endpoints.jsonl + parameters.jsonl from parameter_intelligence ---
    endpoints_rows = []
    parameters_rows = []
    pi_path = os.path.join(rd, "detection", "parameter_intelligence.json")
    if os.path.exists(pi_path):
        try:
            with open(pi_path) as fh:
                pi = json.load(fh)
            for i, ep in enumerate(pi.get("endpoints") or []):
                path_s = ep.get("endpoint") or ""
                endpoints_rows.append({
                    "schema": "bugbountyci.endpoint.v1",
                    "run_id": run_id,
                    "target": target,
                    "endpoint": path_s,
                    "parameter_count": len(ep.get("parameters") or []),
                    "provenance": "detection/parameter_intelligence.json",
                })
                for prm in (ep.get("parameters") or []):
                    parameters_rows.append({
                        "schema": "bugbountyci.parameter.v1",
                        "run_id": run_id,
                        "target": target,
                        "endpoint": path_s,
                        "name": prm.get("name"),
                        "sources": prm.get("sources") or [],
                        "provenance": "detection/parameter_intelligence.json",
                    })
            for prm in (pi.get("global_parameter_hints") or []):
                parameters_rows.append({
                    "schema": "bugbountyci.parameter.v1",
                    "run_id": run_id,
                    "target": target,
                    "endpoint": "_global",
                    "name": prm.get("name"),
                    "sources": prm.get("sources") or [],
                    "provenance": "detection/parameter_intelligence.json",
                })
        except Exception:
            pass
    with open(os.path.join(rd, "meta", "endpoints.jsonl"), "w") as fh:
        for row in endpoints_rows:
            fh.write(json.dumps(row) + "\n")
    with open(os.path.join(rd, "meta", "parameters.jsonl"), "w") as fh:
        for row in parameters_rows:
            fh.write(json.dumps(row) + "\n")


    # --- vocabulary.json (from smart-fuzzing if present; additive normalize) ---
    vocab_out = {"schema": "bugbountyci.vocabulary.v1", "run_id": run_id, "target": target, "terms": []}
    for vp in (
        "smart-fuzzing/vocabulary.json",
        "detection/vocabulary.json",
    ):
        p = os.path.join(rd, vp)
        if not os.path.isfile(p):
            continue
        try:
            with open(p) as fh:
                raw = json.load(fh)
        except Exception:
            continue
        # support {word: {sources, count}} or {terms: [...]}
        if isinstance(raw, dict) and "terms" in raw:
            vocab_out["terms"] = raw["terms"][:2000]
            vocab_out["provenance"] = vp
            break
        terms = []
        if isinstance(raw, dict):
            for word, meta in list(raw.items())[:2000]:
                if not isinstance(word, str) or word.startswith("schema"):
                    continue
                sources = []
                count = 1
                if isinstance(meta, dict):
                    sources = list(meta.get("sources") or [])
                    count = int(meta.get("count") or len(sources) or 1)
                elif isinstance(meta, list):
                    sources = list(meta)
                    count = len(sources)
                terms.append({
                    "term": word,
                    "sources": sources,
                    "count": count,
                    "category": "APPLICATION_EVIDENCE" if count >= 2 else "TARGET_SEMANTIC",
                })
        # prefer higher multi-source terms first
        terms.sort(key=lambda t: (-t.get("count", 0), t.get("term", "")))
        vocab_out["terms"] = terms[:1500]
        vocab_out["provenance"] = vp
        break
    with open(os.path.join(rd, "meta", "vocabulary.json"), "w") as fh:
        json.dump(vocab_out, fh, indent=2)
        fh.write("\n")

    # --- relationships.jsonl (lightweight edges; no graph DB) ---
    rels = []
    def add_rel(rel_type, src, dst, **kw):
        r = {"schema": "bugbountyci.relationship.v1", "run_id": run_id, "type": rel_type, "from": src, "to": dst}
        r.update(kw)
        rels.append(r)
    for h in hosts[:200]:
        host = h.get("host")
        if not host:
            continue
        for p in (h.get("ports") or [])[:20]:
            add_rel("HOST_HAS_PORT", f"host:{host}", f"port:{host}:{p}", provenance="live/ports.txt")
        for u in (h.get("urls") or [])[:5]:
            add_rel("HOST_HAS_URL", f"host:{host}", f"url:{u}", provenance="live")
    for row in urls_rows[:500]:
        u = row.get("url")
        host = row.get("host")
        path = row.get("path")
        if host and u:
            add_rel("HOST_HAS_URL", f"host:{host}", f"url:{u}", provenance="urls/all.txt")
        if path and path not in ("/", ""):
            add_rel("URL_HAS_PATH", f"url:{u}", f"path:{path}", provenance="urls/all.txt")
    for row in endpoints_rows[:300]:
        ep = row.get("endpoint") or row.get("path")
        if ep:
            add_rel("ENDPOINT_DECLARED", f"endpoint:{ep}", f"endpoint:{ep}", provenance="detection/parameter_intelligence.json")
    for row in parameters_rows[:300]:
        name = row.get("name") or row.get("parameter")
        ep = row.get("endpoint") or ""
        if name:
            add_rel("ENDPOINT_HAS_PARAMETER", f"endpoint:{ep}", f"param:{name}", provenance="detection/parameter_intelligence.json")
    with open(os.path.join(rd, "meta", "relationships.jsonl"), "w") as fh:
        for r in rels[:5000]:
            fh.write(json.dumps(r) + "\n")


    urls_n = nlines("urls/all.txt")
    if urls_n == 0:
        # fallback from phase
        try:
            urls_n = int(str((phases.get("url_collection") or {}).get("detail", "0")).split("=")[-1].split()[0])
        except Exception:
            urls_n = 0

    profile = {
        "schema": "bugbountyci.target_profile.v1",
        "run_id": run_id,
        "target": target,
        "counts": {
            "resolved_hosts": nlines("subdomains/resolved.txt"),
            "live_hosts": nlines("live/live.txt"),
            "verified_hosts": nlines("live/verified.txt"),
            "ports": nlines("live/ports.txt"),
            "urls": urls_n,
            "arjun_params": nlines("targeted/arjun_params.txt"),
            "nuclei_findings": nlines("nuclei/findings.jsonl"),
            "hosts_modeled": len(hosts),
            "observations": len(observations),
            "urls_modeled": len(urls_rows),
            "endpoints_modeled": len(endpoints_rows),
            "parameters_modeled": len(parameters_rows),
            "vocabulary_terms": len(vocab_out.get("terms") or []),
            "relationships": len(rels),
        },
        "phase_summary": {k: v.get("status") for k, v in phases.items()},
    }
    with open(os.path.join(rd, "meta", "target_profile.json"), "w") as fh:
        json.dump(profile, fh, indent=2)
        fh.write("\n")

    print(
        f"Wrote meta/engine_health.json + target_profile.json + "
        f"hosts.jsonl ({len(hosts)}) + observations.jsonl ({len(observations)}) + "
        f"urls.jsonl ({len(urls_rows)}) + endpoints.jsonl ({len(endpoints_rows)}) + "
        f"parameters.jsonl ({len(parameters_rows)}) + "
        f"vocabulary.json ({len(vocab_out.get('terms') or [])}) + "
        f"relationships.jsonl ({len(rels)})"
    )

if __name__ == "__main__":
    main()
