#!/usr/bin/env python3
import json, os, sys
REQUIRED = [
    ("meta/engine_health.json", "bugbountyci.engine_health.v1"),
    ("meta/target_profile.json", "bugbountyci.target_profile.v1"),
    ("meta/hosts.jsonl", None),
    ("meta/observations.jsonl", "bugbountyci.observation.v1"),
    ("meta/urls.jsonl", "bugbountyci.url.v1"),
    ("meta/endpoints.jsonl", "bugbountyci.endpoint.v1"),
    ("meta/parameters.jsonl", "bugbountyci.parameter.v1"),
    ("meta/vocabulary.json", "bugbountyci.vocabulary.v1"),
    ("meta/relationships.jsonl", "bugbountyci.relationship.v1"),
    ("meta/response_clusters.json", "bugbountyci.response_clusters.v1"),
    ("meta/recon_export.json", "bugbountyci.recon_export.v1"),
]
def main():
    if len(sys.argv) < 2: return 2
    rd, errors = sys.argv[1], []
    for rel, schema in REQUIRED:
        path = os.path.join(rd, rel)
        if not os.path.isfile(path):
            errors.append(f"MISSING {rel}"); continue
        try:
            if rel.endswith(".jsonl"):
                rows = [json.loads(l) for i,l in enumerate(open(path)) if l.strip() and i < 3]
                if schema and rows and rows[0].get("schema") != schema:
                    errors.append(f"SCHEMA {rel}")
            else:
                data = json.load(open(path))
                if schema and data.get("schema") != schema:
                    errors.append(f"SCHEMA {rel}")
        except Exception as e:
            errors.append(f"PARSE {rel}: {e}")
    if errors:
        print("FAIL"); [print(" ", e) for e in errors]; return 1
    print("OK"); return 0
if __name__ == "__main__":
    sys.exit(main())
