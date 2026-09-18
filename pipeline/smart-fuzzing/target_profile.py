#!/usr/bin/env python3
"""
target_profile.py — V1

Reads the recon artifacts BugBountyCI already produces (nothing new is
scanned here) and turns them into a single structured picture of the
target: which hosts, which technologies, whether an API/GraphQL/Swagger
surface exists, and basic counts.

Inputs (all optional — missing files just mean "unknown", never a crash):
  <RD>/live/tech.json                 technology fingerprints
  <RD>/live/live.txt                  live hosts
  <RD>/js/swagger.txt                 swagger/OpenAPI hits
  <RD>/js/graphql.txt                 graphql hits
  <RD>/js/admin.txt                   admin panel hits
  <RD>/js_deep/linkfinder_endpoints.txt
  <RD>/urls/all.txt
  <RD>/urls/gf_categorized.txt
  <RD>/targeted/arjun_params.txt

Output:
  <RD>/smart-fuzzing/target_profile.json
"""
import argparse
import json
import os


def read_lines(path):
    if not path or not os.path.isfile(path):
        return []
    with open(path, "r", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


def read_json(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return None


def extract_technologies(tech_json):
    """tech.json's exact shape isn't guaranteed across httpx versions, so
    this stays defensive: walk whatever structure is there and pull out
    anything that looks like a technology name."""
    techs = set()
    if not tech_json:
        return []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.lower() in ("tech", "technologies", "technology"):
                    if isinstance(v, list):
                        for t in v:
                            if isinstance(t, str):
                                techs.add(t)
                    elif isinstance(v, str):
                        techs.add(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(tech_json)
    return sorted(techs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True, help="results/<timestamp> directory")
    ap.add_argument("--target", required=True)
    args = ap.parse_args()

    rd = args.results_dir
    out_dir = os.path.join(rd, "smart-fuzzing")
    os.makedirs(out_dir, exist_ok=True)

    tech_json = read_json(os.path.join(rd, "live", "tech.json"))
    technologies = extract_technologies(tech_json)

    hosts = read_lines(os.path.join(rd, "live", "live.txt"))
    swagger = read_lines(os.path.join(rd, "js", "swagger.txt"))
    graphql = read_lines(os.path.join(rd, "js", "graphql.txt"))
    admin = read_lines(os.path.join(rd, "js", "admin.txt"))
    js_endpoints = read_lines(os.path.join(rd, "js_deep", "linkfinder_endpoints.txt"))
    urls_all = read_lines(os.path.join(rd, "urls", "all.txt"))
    urls_gf = read_lines(os.path.join(rd, "urls", "gf_categorized.txt"))
    params = read_lines(os.path.join(rd, "targeted", "arjun_params.txt"))

    profile = {
        "target": args.target,
        "hosts": hosts,
        "host_count": len(hosts),
        "technologies": technologies,
        "api_present": bool(swagger or graphql or js_endpoints),
        "swagger_present": bool(swagger),
        "graphql_present": bool(graphql),
        "admin_surface_present": bool(admin),
        "js_endpoint_count": len(js_endpoints),
        "url_count": len(set(urls_all) | set(urls_gf)),
        "parameter_count": len(params),
        "sources": {
            "tech": "live/tech.json",
            "hosts": "live/live.txt",
            "swagger": "js/swagger.txt",
            "graphql": "js/graphql.txt",
            "admin": "js/admin.txt",
            "js_endpoints": "js_deep/linkfinder_endpoints.txt",
            "urls": ["urls/all.txt", "urls/gf_categorized.txt"],
            "parameters": "targeted/arjun_params.txt",
        },
    }

    out_path = os.path.join(out_dir, "target_profile.json")
    with open(out_path, "w") as f:
        json.dump(profile, f, indent=2)

    print(f"✅ target_profile.json written ({len(technologies)} tech, {len(hosts)} hosts, "
          f"api_present={profile['api_present']}) -> {out_path}")


if __name__ == "__main__":
    main()
