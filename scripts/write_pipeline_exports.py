#!/usr/bin/env python3
"""Write pipeline meta exports: health, profile, hosts, observations, surface, vocabulary, relationships.
Called from Pipeline Health Report after pipeline_health.md is written.
Does not replace raw evidence.
"""
import json, glob, os, re, sys
from urllib.parse import urlparse

def _count_secret_candidates(path):
    try:
        with open(path) as fh:
            data = json.load(fh)
        return len(data.get("candidates") or [])
    except Exception:
        return 0


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

    # Enrich health phases from intelligence summaries when dedicated phase
    # files were not written (e.g. pre-phase-write SHAs, or engines that only
    # emit summary JSON). Does not invent success — copies measured fields.
    def _enrich_phase(name, summary_rel, status_fn, detail_fn):
        if name in phases:
            return
        sp = os.path.join(rd, summary_rel)
        if not os.path.isfile(sp):
            return
        try:
            with open(sp, encoding="utf-8", errors="replace") as fh:
                s = json.load(fh)
        except Exception:
            return
        phases[name] = {
            "phase": name,
            "status": status_fn(s),
            "detail": detail_fn(s),
            "source": summary_rel,
        }

    _enrich_phase(
        "historical_validation",
        "info_disclosure/historical_validation_summary.json",
        lambda s: "ok",
        lambda s: (
            f"validated={s.get('validated',0)} not_run={s.get('not_run',0)} "
            f"outcomes={s.get('outcomes',{})}"
        ),
    )
    _enrich_phase(
        "representation_differential",
        "info_disclosure/representation_summary.json",
        lambda s: "ok" if (s.get("pairs_run") or 0) > 0 or (s.get("candidates") or 0) == 0 else "PARTIAL",
        lambda s: (
            f"candidates={s.get('candidates',0)} pairs_run={s.get('pairs_run',0)} "
            f"kinds={s.get('kinds',{})} diagnosis={s.get('diagnosis','')}"
        ),
    )
    _enrich_phase(
        "historical_pivot",
        "info_disclosure/historical_pivot_summary.json",
        lambda s: "ok",
        lambda s: f"total={s.get('total',0)} counts={s.get('counts',{})}",
    )

    flags = []
    # re-derive minimal flags from phases for machine health
    arj = phases.get("arjun") or {}
    if str(arj.get("status", "")).upper() in ("PARTIAL", "ERROR"):
        flags.append(f"Arjun phase={arj.get('status')} — {arj.get('detail','')}")
    nuc = phases.get("nuclei") or {}
    if str(nuc.get("status", "")).upper() == "PARTIAL":
        flags.append(f"Nuclei phase=PARTIAL — {nuc.get('detail','')}")
    # Nuclei NOT_RUN / moved to VulnRadar is intentional — not a health failure

    overall = "DEGRADED" if flags else "OK"
    # prefer pipeline_health overall + Flags section when present (#142: overall
    # was BROKEN from AI-provider flags, but engine_health.flags stayed empty
    # because only arjun/nuclei phases were re-derived here).
    ph = os.path.join(rd, "meta", "pipeline_health.md")
    if os.path.exists(ph):
        try:
            in_flags = False
            md_flags = []
            for line in open(ph, encoding="utf-8", errors="replace"):
                if line.startswith("## Overall:"):
                    overall = line.split("## Overall:", 1)[1].strip()
                    in_flags = False
                    continue
                if line.startswith("## Flags"):
                    in_flags = True
                    continue
                if in_flags:
                    if line.startswith("## "):
                        in_flags = False
                        continue
                    s = line.strip()
                    if s.startswith("- "):
                        md_flags.append(s[2:].strip())
            if md_flags:
                # Prefer the human health report flags as authoritative list
                flags = md_flags
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
    # Prefer verified HTTP hostnames; cap pure-IP LIVE hosts to limit export noise.
    IP_HOST_CAP = 200
    ip_hosts_kept = 0
    for u in live_urls:
        try:
            p = urlparse(u if "://" in u else "http://" + u)
        except Exception:
            continue
        host = (p.hostname or "").lower()
        if not host or host in seen:
            continue
        is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
        is_verified = any(
            (urlparse(v).hostname or "").lower() == host for v in verified
        )
        if is_ip and not is_verified:
            if ip_hosts_kept >= IP_HOST_CAP:
                continue
            ip_hosts_kept += 1
        seen.add(host)
        host_ports = sorted(ports_by_ip.get(host, [])) if is_ip else []
        host_class = "VERIFIED_HTTP" if is_verified else "LIVE_HTTP"
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
    rd_path = os.path.join(rd, "smart-fuzzing", "response_diffs.json")
    if os.path.isfile(rd_path):
        try:
            with open(rd_path) as fh:
                diffs = json.load(fh)
            items = diffs if isinstance(diffs, list) else (diffs.get("hits") or diffs.get("results") or [])
            n_rd = 0
            for it in (items if isinstance(items, list) else []):
                if not isinstance(it, dict):
                    continue
                cls = (it.get("classification") or it.get("class") or "").upper()
                if cls in ("DUPLICATE", "NOISE", "UNKNOWN", ""):
                    continue
                if n_rd >= 40:
                    break
                add_obs(
                    observation_id=f"rdiff-{n_rd}",
                    engine="smart_fuzzing/response_diff",
                    url=it.get("url") or it.get("input"),
                    observed_behavior=cls or "response_diff",
                    status=str(it.get("status") or ""),
                    classification="SIGNAL" if cls == "INTERESTING" else "LEAD",
                    confidence="medium" if cls == "INTERESTING" else "low",
                    detail=(it.get("reason") or "")[:200],
                    provenance="smart-fuzzing/response_diffs.json",
                )
                n_rd += 1
        except Exception:
            pass
    # Historical validation outcomes → canonical observations (Phase 2 contract)
    hv_path = os.path.join(rd, "info_disclosure", "historical_validations.jsonl")
    if os.path.isfile(hv_path):
        try:
            n_hv = 0
            with open(hv_path, "r", errors="ignore") as fh:
                for line in fh:
                    if not line.strip() or n_hv >= 80:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    outcome = row.get("outcome") or ""
                    if outcome in ("NOT_RUN", ""):
                        continue
                    # Prefer substantive outcomes for observation stream
                    if outcome == "REDIRECTED" and n_hv >= 20:
                        continue
                    add_obs(
                        observation_id=f"hist-val-{n_hv}",
                        engine="historical_validation",
                        url=row.get("validation_url") or row.get("historical_url"),
                        observed_behavior=outcome,
                        status=str(row.get("status") or outcome),
                        classification=(
                            "SIGNAL" if outcome == "CURRENTLY_REACHABLE"
                            else "LEAD" if outcome in ("REDIRECTED", "BLOCKED_OR_RATE_LIMITED")
                            else "NEGATIVE"
                        ),
                        confidence=row.get("confidence") or "low",
                        detail=(row.get("not_run_reason") or row.get("location") or "")[:200],
                        limitations=row.get("limitations"),
                        provenance="info_disclosure/historical_validations.jsonl",
                        historical_path=row.get("historical_path"),
                        evidence_ladder=row.get("evidence_ladder"),
                    )
                    n_hv += 1
        except Exception:
            pass
    # Representation MEANINGFUL only
    rep_path = os.path.join(rd, "info_disclosure", "representation_diffs.jsonl")
    if os.path.isfile(rep_path):
        try:
            n_rep = 0
            with open(rep_path, "r", errors="ignore") as fh:
                for line in fh:
                    if not line.strip() or n_rep >= 40:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    if row.get("outcome") != "MEANINGFUL_DIFFERENTIAL":
                        continue
                    add_obs(
                        observation_id=f"repdiff-{n_rep}",
                        engine="representation_differential",
                        url=row.get("url"),
                        observed_behavior="MEANINGFUL_DIFFERENTIAL",
                        status="SUCCESS",
                        classification="SIGNAL",
                        confidence="medium",
                        detail=str((row.get("differential") or {}).get("signals") or "")[:200],
                        limitations="observational Accept differential — not a vulnerability",
                        provenance="info_disclosure/representation_diffs.jsonl",
                        evidence_ladder=row.get("evidence_ladder"),
                    )
                    n_rep += 1
        except Exception:
            pass
    for phase_name, ph in phases.items():
        st = (ph or {}).get("status") or ""
        if st.upper() in ("PARTIAL", "ERROR", "EMPTY") or st.lower() in ("partial", "error", "empty"):
            add_obs(
                observation_id=f"phase-{phase_name}",
                engine=phase_name,
                observed_behavior="phase_status",
                status=st,
                classification="HEALTH",
                confidence="high",
                detail=(ph or {}).get("detail"),
                provenance=f"meta/phases/{phase_name}.json",
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
    # Merge LinkFinder API_ROUTE into endpoint surface (dedupe by path)
    try:
        seen_ep = {(r.get("endpoint") or "").rstrip("/") for r in endpoints_rows}
        npath = os.path.join(rd, "js_deep", "linkfinder_normalized.jsonl")
        if os.path.isfile(npath):
            with open(npath) as fh:
                for line in fh:
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    if (row.get("classification") or "").upper() != "API_ROUTE":
                        continue
                    path = row.get("path") or ""
                    if not path:
                        u = row.get("raw_value") or ""
                        if u.startswith("/"):
                            path = u.split("?")[0]
                        elif u.startswith("http"):
                            try:
                                path = urlparse(u).path or ""
                            except Exception:
                                path = ""
                    path = (path or "").split("?")[0]
                    key = path.rstrip("/") or path
                    if not key or key == "/" or key.startswith("/ROOT/") or key in seen_ep:
                        continue
                    seen_ep.add(key)
                    endpoints_rows.append({
                        "schema": "bugbountyci.endpoint.v1",
                        "run_id": run_id,
                        "target": target,
                        "endpoint": path,
                        "parameter_count": 0,
                        "provenance": "js_deep/linkfinder_normalized.jsonl",
                        "classification": "API_ROUTE",
                        "source_js": row.get("source_js"),
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
        if not isinstance(raw, dict):
            continue
        terms = []
        # Normalized contract: schema + terms list
        if str(raw.get("schema") or "").startswith("bugbountyci.vocabulary") and isinstance(raw.get("terms"), list):
            for item in raw["terms"][:2000]:
                if isinstance(item, dict) and (item.get("term") or item.get("word")):
                    terms.append(item)
        else:
            # Live smart-fuzzing shape: {word: count} or {word: {sources, count}}
            # NOTE: a word can literally be "terms" — do not treat that as schema.
            for word, meta in list(raw.items())[:3000]:
                if not isinstance(word, str) or word in ("schema", "run_id", "target", "provenance"):
                    continue
                sources = []
                count = 1
                if isinstance(meta, dict):
                    sources = list(meta.get("sources") or [])
                    try:
                        count = int(meta.get("count") or len(sources) or 1)
                    except (TypeError, ValueError):
                        count = 1
                elif isinstance(meta, (int, float)):
                    count = int(meta)
                elif isinstance(meta, list):
                    sources = list(meta)
                    count = len(sources)
                terms.append({
                    "term": word,
                    "sources": sources,
                    "count": count,
                    "category": "APPLICATION_EVIDENCE" if count >= 2 else "TARGET_SEMANTIC",
                })
        if not terms:
            continue
        terms.sort(key=lambda x: (-int(x.get("count") or 0), str(x.get("term") or "")))
        vocab_out["terms"] = terms[:1500]
        vocab_out["provenance"] = vp
        break
    try:
        with open(os.path.join(rd, "meta", "vocabulary.json"), "w") as fh:
            json.dump(vocab_out, fh, indent=2)
            fh.write("\n")
    except Exception as e:
        print(f"⚠️ vocabulary export failed: {e}")

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
    # Source map → endpoint/path (from source_maps/endpoints.txt)
    try:
        sm = os.path.join(rd, "source_maps", "endpoints.txt")
        if os.path.isfile(sm):
            with open(sm) as fh:
                for i, line in enumerate(fh):
                    if i >= 400:
                        break
                    ep = line.strip()
                    if not ep or ep.startswith("#"):
                        continue
                    # Keep path-like or URL-like only
                    if ep.startswith("http") or ep.startswith("/") or "://" in ep or "/" in ep:
                        add_rel("SOURCE_MAP_TO_ENDPOINT", "sourcemap:found", f"endpoint:{ep[:200]}", provenance="source_maps/endpoints.txt")
    except Exception:
        pass
    # HISTORICAL_URL → seed from wayback (relationship only; not a finding)
    try:
        for fname in ("wayback.txt", "gau.txt"):
            wp = os.path.join(rd, "urls", fname)
            if not os.path.isfile(wp):
                continue
            with open(wp) as fh:
                for i, line in enumerate(fh):
                    if i >= 200:
                        break
                    u = line.strip().split()[0] if line.strip() else ""
                    if not u.startswith("http"):
                        continue
                    add_rel("HISTORICAL_URL", f"archive:{fname}", f"url:{u[:200]}", provenance=f"urls/{fname}")
    except Exception:
        pass
    # V3: JS -> ENDPOINT from LinkFinder — API_ROUTE first, then WEB_ROUTE (cap 400)
    # Prioritize API so a WEB-heavy corpus cannot starve the relationship export.
    try:
        npath = os.path.join(rd, "js_deep", "linkfinder_normalized.jsonl")
        added = 0
        if os.path.isfile(npath):
            records = []
            with open(npath) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    cls = rec.get("classification")
                    if cls not in ("API_ROUTE", "WEB_ROUTE"):
                        continue
                    ep = (rec.get("resolved_url") or rec.get("raw_value") or "").strip().rstrip("\\")
                    if not ep:
                        continue
                    records.append(rec)
            # API_ROUTE before WEB_ROUTE
            records.sort(key=lambda r: 0 if r.get("classification") == "API_ROUTE" else 1)
            for rec in records:
                if added >= 400:
                    break
                cls = rec.get("classification")
                ep = (rec.get("resolved_url") or rec.get("raw_value") or "").strip().rstrip("\\")
                src_js = rec.get("source_js") or "linkfinder"
                add_rel(
                    "JS_TO_ENDPOINT",
                    f"js:{src_js[:80]}",
                    f"endpoint:{ep[:200]}",
                    provenance="js_deep/linkfinder_normalized.jsonl",
                    classification=cls,
                )
                added += 1
        else:
            lf = os.path.join(rd, "js_deep", "linkfinder_endpoints.txt")
            if os.path.isfile(lf):
                with open(lf) as fh:
                    for i, line in enumerate(fh):
                        if i >= 400:
                            break
                        ep = line.strip()
                        if not ep or ep.startswith("#"):
                            continue
                        add_rel(
                            "JS_TO_ENDPOINT",
                            "js:linkfinder",
                            f"endpoint:{ep[:200]}",
                            provenance="js_deep/linkfinder_endpoints.txt",
                        )
    except Exception:
        pass
    # V3: JS -> API surface from swagger/graphql hits
    try:
        for fname, kind in (("swagger.txt", "openapi"), ("graphql.txt", "graphql")):
            fp = os.path.join(rd, "js", fname)
            if not os.path.isfile(fp):
                continue
            with open(fp) as fh:
                for i, line in enumerate(fh):
                    if i >= 100:
                        break
                    url = line.strip()
                    if not url or url.startswith("#"):
                        continue
                    add_rel("JS_TO_API", f"js:{kind}", f"url:{url[:200]}", provenance=f"js/{fname}", api_style=kind)
    except Exception:
        pass
    # V3: HOST -> ENDPOINT from endpoints rows
    try:
        for row in endpoints_rows[:300]:
            ep = row.get("endpoint") or row.get("path")
            host = row.get("host")
            if ep and host:
                add_rel("HOST_TO_ENDPOINT", f"host:{host}", f"endpoint:{ep[:200]}", provenance="meta/endpoints.jsonl")
    except Exception:
        pass
    # V3: ENDPOINT -> RESPONSE_CLUSTER sample links from response_diffs
    try:
        rdp = os.path.join(rd, "smart-fuzzing", "response_diffs.json")
        if os.path.isfile(rdp):
            with open(rdp) as fh:
                diffs = json.load(fh)
            items = diffs if isinstance(diffs, list) else []
            for it in items[:200]:
                if not isinstance(it, dict):
                    continue
                cls = it.get("classification") or "UNKNOWN"
                url = it.get("url") or ""
                if url:
                    add_rel("URL_TO_RESPONSE_CLASS", f"url:{url[:200]}", f"class:{cls}", provenance="smart-fuzzing/response_diffs.json")
    except Exception:
        pass

    # Cross-engine: HISTORICAL path ∩ LinkFinder API_ROUTE (same path identity)
    # Not a finding — relationship only for research prioritization.
    try:
        hist_paths = set()
        for fname in ("wayback.txt", "gau.txt", "waybackurls.txt"):
            wp = os.path.join(rd, "urls", fname)
            if not os.path.isfile(wp):
                continue
            with open(wp) as fh:
                for i, line in enumerate(fh):
                    if i >= 5000:
                        break
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        path = urlparse(line if "://" in line else "https://x" + (line if line.startswith("/") else "/" + line)).path or "/"
                    except Exception:
                        path = line.split("?")[0] if line.startswith("/") else "/"
                    if path and path != "/":
                        hist_paths.add(path.rstrip("/") or path)
        api_paths = set()
        npath = os.path.join(rd, "js_deep", "linkfinder_normalized.jsonl")
        if os.path.isfile(npath):
            with open(npath) as fh:
                for line in fh:
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    cls = (row.get("classification") or row.get("class") or "").upper()
                    if cls not in ("API_ROUTE", "WEB_ROUTE"):
                        continue
                    path = row.get("path") or row.get("endpoint") or ""
                    if not path:
                        u = row.get("url") or row.get("raw") or row.get("raw_value") or ""
                        if u.startswith("http"):
                            try:
                                path = urlparse(u).path or ""
                            except Exception:
                                path = ""
                        elif u.startswith("/"):
                            path = u.split("?")[0]
                    path = (path or "").split("?")[0]
                    if path and path != "/" and not path.startswith("/ROOT/"):
                        api_paths.add(path.rstrip("/") or path)
        # also historical_pivots.jsonl if present
        hp = os.path.join(rd, "info_disclosure", "historical_pivots.jsonl")
        if os.path.isfile(hp):
            with open(hp) as fh:
                for line in fh:
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    path = row.get("path") or ""
                    if path and path != "/":
                        hist_paths.add(path.rstrip("/") or path)
        overlap = hist_paths & api_paths
        for path in sorted(overlap)[:300]:
            add_rel(
                "HISTORICAL_PATH_AND_JS_API",
                f"historical_path:{path[:200]}",
                f"js_api:{path[:200]}",
                provenance="urls/*+js_deep/linkfinder_normalized.jsonl",
                engines=["historical", "linkfinder"],
            )
    except Exception:
        pass
    # Secret candidate → JS file (fingerprint only; not Hunter promotion)
    try:
        scp = os.path.join(rd, "meta", "secret_candidates_si4.json")
        if not os.path.isfile(scp):
            scp = os.path.join(rd, "meta", "secret_candidates.json")
        if os.path.isfile(scp):
            with open(scp) as fh:
                sc = json.load(fh)
            for c in (sc.get("candidates") or [])[:200]:
                f = c.get("file") or ""
                cid = c.get("candidate_id") or ""
                if f and cid:
                    add_rel(
                        "SECRET_CANDIDATE_TO_JS_FILE",
                        f"secret:{cid}",
                        f"js_file:{f[:200]}",
                        provenance="meta/secret_candidates*.json",
                        classification=c.get("classification") or "LEAD",
                    )
    except Exception:
        pass


    # Cross-engine: LinkFinder/JS API or WEB route path also modeled as live endpoint
    try:
        live_eps = set()
        for row in endpoints_rows[:2000]:
            ep = (row.get("endpoint") or row.get("path") or "").split("?")[0]
            if ep and ep != "/":
                live_eps.add(ep.rstrip("/") or ep)
        js_paths = set()
        npath = os.path.join(rd, "js_deep", "linkfinder_normalized.jsonl")
        if os.path.isfile(npath):
            with open(npath) as fh:
                for line in fh:
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    cls = (row.get("classification") or "").upper()
                    if cls not in ("API_ROUTE", "WEB_ROUTE"):
                        continue
                    path = row.get("path") or ""
                    if not path:
                        u = row.get("raw_value") or ""
                        if u.startswith("/"):
                            path = u.split("?")[0]
                        elif u.startswith("http"):
                            try:
                                path = urlparse(u).path or ""
                            except Exception:
                                path = ""
                    path = (path or "").split("?")[0]
                    if path and path != "/" and not path.startswith("/ROOT/"):
                        js_paths.add(path.rstrip("/") or path)
        for path in sorted(js_paths & live_eps)[:200]:
            add_rel(
                "JS_API_AND_LIVE_ENDPOINT",
                f"js_path:{path[:200]}",
                f"endpoint:{path[:200]}",
                provenance="js_deep/linkfinder_normalized.jsonl+meta/endpoints.jsonl",
                engines=["linkfinder", "endpoint_model"],
            )
    except Exception:
        pass

    with open(os.path.join(rd, "meta", "relationships.jsonl"), "w") as fh:
        for r in rels[:5000]:
            fh.write(json.dumps(r) + "\n")



    # --- response_clusters.json from smart-fuzzing response_diffs if present ---
    clusters = {"schema": "bugbountyci.response_clusters.v1", "run_id": run_id, "target": target, "clusters": []}
    rd_path = os.path.join(rd, "smart-fuzzing", "response_diffs.json")
    if os.path.isfile(rd_path):
        try:
            with open(rd_path) as fh:
                diffs = json.load(fh)
            by_cls = {}
            items = diffs if isinstance(diffs, list) else (diffs.get("hits") or diffs.get("results") or [])
            if isinstance(diffs, dict) and not items:
                # maybe map url->detail
                items = [{"url": k, **(v if isinstance(v, dict) else {})} for k, v in diffs.items() if k not in ("schema",)]
            for it in items if isinstance(items, list) else []:
                if not isinstance(it, dict):
                    continue
                cls = it.get("classification") or it.get("class") or "UNKNOWN"
                by_cls.setdefault(cls, []).append({
                    "url": it.get("url") or it.get("input"),
                    "status": it.get("status"),
                    "reason": (it.get("reason") or "")[:200],
                })
            for cls, samples in sorted(by_cls.items()):
                clusters["clusters"].append({
                    "classification": cls,
                    "count": len(samples),
                    "samples": samples[:20],
                })
            clusters["provenance"] = "smart-fuzzing/response_diffs.json"
        except Exception as e:
            clusters["error"] = str(e)[:200]
    with open(os.path.join(rd, "meta", "response_clusters.json"), "w") as fh:
        json.dump(clusters, fh, indent=2)
        fh.write("\n")

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
            "response_clusters": len(clusters.get("clusters") or []),
            "secret_candidates": _count_secret_candidates(os.path.join(rd, "meta", "secret_candidates.json")),
            "secret_candidates_si4": _count_secret_candidates(os.path.join(rd, "meta", "secret_candidates_si4.json")),
            "secret_suppressed": nlines("meta/secret_suppressed.jsonl"),
        },
        "phase_summary": {k: v.get("status") for k, v in phases.items()},
    }
    with open(os.path.join(rd, "meta", "target_profile.json"), "w") as fh:
        json.dump(profile, fh, indent=2)
        fh.write("\n")

    stable = {
        "schema": "bugbountyci.recon_export.v1",
        "run_id": run_id,
        "target": target,
        "overall_health": eng.get("overall"),
        "artifacts": {
            "engine_health": "meta/engine_health.json",
            "target_profile": "meta/target_profile.json",
            "hosts": "meta/hosts.jsonl",
            "observations": "meta/observations.jsonl",
            "urls": "meta/urls.jsonl",
            "endpoints": "meta/endpoints.jsonl",
            "parameters": "meta/parameters.jsonl",
            "vocabulary": "meta/vocabulary.json",
            "relationships": "meta/relationships.jsonl",
            "response_clusters": "meta/response_clusters.json",
            "response_ranking": "smart-fuzzing/response_ranking.json",
            "strategy_outcome": "smart-fuzzing/strategy_outcome.json",
            "metrics": "detection/metrics.json",
            "hunter_queue": "detection/hunter_queue.md",
            "historical_pivots": "info_disclosure/historical_pivots.jsonl",
            "historical_validations": "info_disclosure/historical_validations.jsonl",
            "representation_diffs": "info_disclosure/representation_diffs.jsonl",
            "linkfinder_summary": "js_deep/linkfinder_summary.json",
            "linkfinder_normalized": "js_deep/linkfinder_normalized.jsonl",
            "smart_fuzzing_metrics": "smart-fuzzing/metrics.json",
            "nuclei_track": "meta/nuclei_track.json",
            "sra_handoff": "meta/sra_handoff.json",
            "secret_candidates": "meta/secret_candidates.json",
            "secret_candidates_si4": "meta/secret_candidates_si4.json",
            "secret_suppressed": "meta/secret_suppressed.jsonl",
        },
        "counts": profile.get("counts"),
        "limitations": eng.get("flags") or [],
        "boundary": "BugBountyCI recon producer only; no SRA architecture",
    }
    with open(os.path.join(rd, "meta", "recon_export.json"), "w") as fh:
        json.dump(stable, fh, indent=2)
        fh.write("\n")
    print(
        f"Wrote meta/engine_health.json + target_profile.json + "
        f"hosts.jsonl ({len(hosts)}) + observations.jsonl ({len(observations)}) + "
        f"urls.jsonl ({len(urls_rows)}) + endpoints.jsonl ({len(endpoints_rows)}) + "
        f"parameters.jsonl ({len(parameters_rows)}) + "
        f"vocabulary.json ({len(vocab_out.get('terms') or [])}) + "
        f"relationships.jsonl ({len(rels)}) + "
        f"response_clusters.json ({len(clusters.get('clusters') or [])})"
    )

if __name__ == "__main__":
    main()
